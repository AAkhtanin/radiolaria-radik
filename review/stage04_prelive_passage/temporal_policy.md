# Dynamic informational temporal policy

This is an owned application policy for new informational material. It is not a
reference-kernel rule, effect consent or an execution observation. The shared,
I/O-free source is `app/dynamic_temporal.py`, policy
`radik.dynamic.temporal.v01`: a 7200-second reuse window and a 10800-second
informational horizon. The existing 600-second request deadline and
3600-second role-round bound are unchanged.

| Bound | Original anchor | Effective upper limit and consumer |
| --- | --- | --- |
| Current informational policy | Controller or runtime policy-reader creation | Anchor + 10800; each read still binds the exact owned source-policy bytes. Changed or expired policy refuses. |
| Current family | Checked Orchestrator consumption, or fresh memory-route construction | `min(anchor + 10800, current policy expiry)`; checked before Architect and every native dispatch. |
| WorldState / current TemporalQuery | Current family creation | WorldState retains the family expiry. Query max age is the remaining family interval; its `as_of` and evaluation point remain the actual original observation. |
| SemanticArchitectProposal / Work topology | Actual semantic proposal creation | TTL is the remaining interval to family expiry; explicit validity and TTL both end there. Public Work projections inherit this envelope. |
| Required nested G2C/G2D routing projection | Actual required-review construction | `min(anchor + 10800, actual semantic validity expiry, semantic creation + TTL)`; actual routing validity and TTL are both retained as acceptance caps. |
| Final local Root | Actual final review time | The caller checks current source/family/policy and finite caps. The public Root adapter has temporal validity and time-reference fields, with no independent fixed numeric lifetime. New final Root material includes the exact accepted clock and chosen cap evidence. |
| New fresh accepted result | Actual final acceptance time | `min(anchor + 7200, family, policy, actual semantic validity/TTL, applicable actual nested routing validity/TTL)`; exact expiry refuses. |
| New dynamic DRS writeback | Original accepted time | `min(accepted expiry, original accepted time + requested TTL, original accepted time + 7200)`; omitted dynamic TTL resolves to 7200. An explicit shorter TTL remains shorter. The legacy document default remains 3600. |
| Current dynamic selection | Original record envelope and current evaluation | The real DRS validator requires current validity, original creation + original TTL, and original age below `min(record TTL, 7200)`, plus current sources/policy, fresh Root descent and exact readback. |
| Warm and warm-again result/writeback | Original historical accepted time | Retain that anchor; expiry is additionally capped by the selected record's original expiry and all narrower current consumer caps. Neither restart nor writeback grants a new reuse window. |

If A has the full 7200-second effective reuse interval at acceptance, a B round
lasting 3600 seconds leaves 3600 seconds for current DRS validation and warm
consumption. Three model request deadlines account for at most 1800 seconds
within B's unchanged role round; native work uses the remaining round interval.
The informational horizon is long enough to leave the full reuse interval when
A finishes within 3600 seconds of policy creation. Earlier source/policy caps,
pre-round overhead or a late acceptance can reduce this margin. The program
uses the actual minimum and refuses at expiry; it does not remove a cap,
refresh an origin, retry a model request or substitute a different memory item.

The inspected public ABI, DRS and G2C time validators require finite/coherent
timestamps, positive or nonnegative TTL as appropriate, and their existing
integer/UTC bounds. They impose no separate 600- or 3600-second maximum on this
informational profile. DRS evaluates validity and TTL with strict upper bounds.
These public predicates remain unchanged.

New accepted bodies contain `temporal_binding`, also consumed in the exact
final Root claim. Persisted validation reconstructs that Root material, checks
the actual review-time relationship and the minimum of the recorded chosen
caps. Changing only outer accepted/expiry clocks and recomputing their outer
SHA cannot preserve this binding. Historical results without this field retain
the earlier fresh-result ceiling of 600 seconds and actual review-time anchor,
or their exact warm origin. Their DRS record clocks and bytes remain the
independent historical basis and are not rewritten under this policy.

Source changes, wrong meaning/provenance, policy withdrawal, expired records
and missing qualified memory retain their existing refusal paths.
`require_memory=True` still refuses before Orchestrator/reservation when actual
DRS selection is absent. Effect policy, consumed CLOSED SAVE quota, PURE
invocation `candidate_id=None` / `packet_id=None`, request/attempt budgets and
the informational G2E blocker remain unchanged.
