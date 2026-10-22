# Radik Stage 5: experience changes the next check, not the rules

**Radik is an interactive application built on the Radiolaria reference kernel and runtime.** Stage 5 adds qualified experience: a recorded observation can change the next admitted check without becoming a rule for every other task.

## An answer is not the end of the task

You ask Radik to explain a support policy. Who is covered? When is support available? What does it cost?

In the recorded example, fictional Service Rowan covers active annual plans, promises a reply to urgent requests within one working day, and excludes telephone support on public holidays. Its document leaves call prices unspecified. Three live model roles produce an accepted explanation: an orchestrator identifies the task, an architect proposes the work, and a critic reviews the result.

Stage 5 then asks a different question: **can a checked observation change what happens next?**

The experience mechanism records an expectation before a native check examines the approved source for explicitly unresolved conditions. The check finds one. This is a defined source check, not a verdict that the model's answer was wrong.

## The next operation actually changes

Before that observation, Radik selects `source_verification`. After the scoped history passes fresh checks, it selects and executes `source_condition_audit` instead. The new result identifies the source's words **“not specified”** and records the next review needed.

The difference is visible in executed native work and its consumed output. It is not just a model saying that it has learned a lesson. [Follow the cold check](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/82fb90d8a0b7/cold_current_consumer_175513f2905df226bad4e3cfd749b61c13dffd43f22b1e7566584b36ac74dcaf.json), [the qualified check](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/82fb90d8a0b7/qualified_current_consumer_00b064abd29144f07e4e9ae85c93748d5e9c830514d10d1211931915ff58b342.json) and [the link between them](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/82fb90d8a0b7/causal_chain_verified_de077a0c5f8e45b58d5184b3e755621a6d249d4623729a78d39a37616a7ea90d.json).

## A lesson stays with the work it belongs to

Next comes a different question about fictional Museum Alder: opening hours, a garden closed during thunderstorms, admission and guided tours.

Radik treats it as a separate task with its own sources and current decisions. Rowan's experience does not become a museum rule, a penalty or a prohibition. Alder performs its own cold verification; Rowan's stored history stays unchanged. [Inspect the separate consumer](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/82fb90d8a0b7/unrelated_current_consumer_0d4022ffea9ff374fe2a0be220509b9a778fd397264f26f6390b6bd40e18fb34.json).

Then Rowan's document changes. The previously admitted source binding is rejected before native dispatch. The old work and history remain available for inspection, but they do not override the new source revision. [Inspect the refusal](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/82fb90d8a0b7/source_revision_stale_binding_refused_aa5922d0f6a42daff6c32121f95bdfc422e6728dfea5adacaf2fcac32785aa67.json).

## The same budget can support a different choice of work

The accepted Stage 5 record also includes an earlier, separately accepted allocation exercise. Seven checks move from four quotation checks and three qualification checks to three quotation checks and four qualification checks. Both runs use the same nine units, including setup and the final consumer. The final work consumes all seven selected outputs.

A prohibited branch stays excluded even when its ranking inputs look attractive. Experience helps choose among permitted work; it does not grant permission. [Compare the earlier cold allocation](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/92737b6ba718/cold_allocated_work_34773b8e2e8f38e61ee9159e4eddf6035c8dfabf3ff711be414406fdf2745d41.json) and [qualified allocation](https://github.com/AAkhtanin/radiolaria-radik/blob/30c2743b44710bfdc2e50cb475d702c15f7099b4/review/stage05_qualified_experience_passage/v10_actual_acceptance/original_actual/workspace/owner_documents/review/stage05/92737b6ba718/qualified_allocated_work_7e4c92374451478e6aa93c8fbd0574f817d601e8df82ef9c48c8323b5b2c781b.json). This is redistribution, not a measured speedup; it was not rerun in the final Rowan/Alder operation.

## What is accepted

All ten original requirements are covered by the final operation and explicitly retained earlier evidence. The final operation completed two tasks and six model-role calls in **885.656256625 seconds**, then closed normally. The call ledger moved from 53 to 59; all five historical UNKNOWN outcomes remained recorded.

The scope is qualified experience in this application, not model-weight training. Source changes, age, expiry, conflict and quarantine retain distinct rules. The final source-revision refusal establishes the changed-source boundary; it does not claim that the old history was still fresh at that later point.

**Capability, not authority. Experience can change the next check. It cannot give the model more authority.**

## Follow the evidence

The [original scenario](README.md), [audit route](AUDIT_LOG.md), [evidence index](claims_evidence.json) and [verification guide](VERIFY.md) remain unchanged. The [formal closure](../../v10_actual_acceptance/stage05_acceptance.json) preserves Stage 4 and closes only the four Stage 5 directions.

The [XML reader](READ_RADIK_STAGE05.xml) is designed for exploration with your own AI assistant. Ask it to follow one chain from expectation to observation, history and actual consumer. The records distinguish fresh executions, retained controls and interpretation. Reading them does not require a new model call or application run.

This page is an editorial reading layer over publication commit `30c2743b44710bfdc2e50cb475d702c15f7099b4`. It does not alter the recorded evidence or start Stage 6.
