# Opaque auxiliary JSON profile

The stream profile is `radik.responses.text_json_stream.v04`. This repair keeps
request settings, transport origin, AUTH, response/sequence identity, lifecycle,
output coverage, returned policy, usage, role validation and all stream/line/event
bounds unchanged. It changes the owned auxiliary resource policy and its safe
observation, without changing native business Work, BSEP, Root or memory clocks.

## Source basis and historical limits

The [official compatibility guidance](https://developers.openai.com/api/reference/overview#backwards-compatibility)
was searched and opened on 2026-10-16. It permits added JSON properties and event
data and changes to opaque strings. This supports a reader that does not invent
an internal telemetry schema. It does not authorize accepting every event or
control signal. The previously read immutable OpenAI Codex source basis remains
commit `6ae8b8aa7c608730d4315d59c5c081897ae02780`, specifically the
[Responses adapter and tests](https://raw.githubusercontent.com/openai/codex/6ae8b8aa7c608730d4315d59c5c081897ae02780/codex-rs/codex-api/src/sse/responses.rs).
No new broad source audit or provider call was made. The companion profile
records the prior supplementary source reads and the absence of a captured raw
source SHA. That source establishes carrier mechanics, not identical behavior
across all routes or the actual nested payload.

Actual124250 observed a metadata object with opaque moderation telemetry. Its
nested literal and exact failed old depth/container/key sublimit remain
`NOT_OBSERVED`. The old 35 fixtures and previous 47 parser observations remain
historical evidence. Their old depth and other narrow opaque-bound refusals are
not desired compatibility constraints under this new version. New inputs are
synthetic and are never called actual replay.

## Two separate layers

| Layer | Behavior |
| --- | --- |
| Metadata envelope | `response.metadata` requires an object, the current response ID and increasing sequence. It cannot produce text, usage or completion. |
| Opaque values and unknown names | Any JSON scalar, array or object is permitted inside opaque fields within the shared byte budget. No independent depth, member count, key length, string length or node count is imposed. Tool-looking prose remains data. |
| Model claims | Every recognized case-insensitive model claim in both header carriers is checked. A malformed claim or any conflict refuses. No claim supplies a missing terminal model. |
| Verification | The recognized verification recommendation refuses explicitly. Unknown recommendations remain informational; the known typed string-array contract remains strict. |
| Moderation | Presence is opaque telemetry. No nested policy or refusal is inferred. Provider failed/incomplete/refusal events remain effective. |
| Buffering | Typed use-case/reason arrays and absent/null retry are passive notifications. Retry/faster-model controls and conflicting recognized carriers refuse. No retry, fallback request or model switch is implemented. |
| Other events/items | The existing finite event profile remains strict. Actual tool events/items and unsupported event families still refuse. |

## One byte-derived resource policy

The canonical combined auxiliary envelope retains its **16384 UTF-8 byte** limit.
It includes metadata, the two optional header carriers and optional buffering.
The existing event, line and total stream bounds apply first. No other opaque
structural limit remains.

`measure_opaque_json` iteratively emits canonical sorted JSON using iterator
frames. Each container/member/scalar consumes canonical bytes; emitted bytes,
active frame depth and traversal work are therefore finite under the same byte
budget. It retains at most 16385 output bytes and stops immediately at the first
crossing. The returned 16385 is a lower bound, not a claim about the full size.
There is no partial-content hash. Scalar encoding and container sorting are also
bounded by the already bounded decoded event. No recursive whole-tree JSON
encoder is used for opaque measurement or hashing. Cyclic/non-JSON direct caller
objects are invalid shapes, rather than accepted provider JSON.

`decode_event_json` uses iterative object/array frames and stdlib string scanning;
it does not depend on Python recursion depth. Strict syntax, duplicate members,
UTF-8 and nonfinite-number checks remain. One explicit technical conversion limit
remains: decimal integer tokens may contain at most **4300 digits**, before sign.
This matches the normal CPython integer-string conversion safety ceiling, is
local and deterministic, and does not change process-global settings. Decimal
chunks make the accepted range independent of any lower process-global setting.
Larger tokens yield `plan_json_integer_digit_limit`, with exact scanned digits
and incomplete event traversal. This is distinct from `plan_metadata_byte_limit`.
The 4300/4301 boundary is reachable within the ordinary byte budget. Nested
arrays/objects have no separate decoder depth ceiling. No artificial node
exhaustion case is invented.

## Safe v03 observation

`radik.public_stream_event_observation.v03` preserves fixed safe structural fields,
last-two auxiliary summaries and count, and adds:

- `resource`: limit kind, measurement, numeric value, exact/lower-bound relation,
  limit and traversal-complete flag. A successful byte measurement is exact;
  an over-budget count is a lower bound.
- `known_refusals` and `known_inspection_complete`: known model/control findings
  are inspected separately and remain visible even when resource is primary.
- `decoder_resource`: an explicit technical integer-token refusal when reached.
- `structure_scope`: complete event, parsed prefix, or not parsed. Root and
  auxiliary unknown-field summaries carry an inspection-complete flag; absent
  root field shapes in a decoded prefix are `NOT_INSPECTED`. Existing name,
  sequence and link fields describe that explicitly scoped prefix only.

After an incomplete decode, a safely observed conflict/requirement can remain
positive evidence, while absence-like conclusions become `NOT_INSPECTED`.
Absent known/header shapes in that prefix also read `NOT_INSPECTED`. If the
decoder stops before any recognizable carrier/type, no auxiliary entry is
invented: the incomplete decoder resource means carrier inspection was not
completed, never that control was absent. Other structural fields describe only
the parsed prefix. Partially decoded raw objects stay private in memory. The refused stream is not
continued to gather more information. Public data contains only closed enums,
numbers and hashes, never raw keys, values, header values or reasoning. The
strict publisher secret filter is unchanged; public keys use `header_shapes`.

The single stdlib projector retains v01 and v02 validation without rewriting old
bytes. New observations pass through the same error projection, primary/secondary
writer path, report/checkpoint/archive readback and stdlib reimport. A source-only
review is required before candidate execution. Synthetic HTTP/grant/catalog
fixtures and isolated archives are not actual provider or owner acceptance.
