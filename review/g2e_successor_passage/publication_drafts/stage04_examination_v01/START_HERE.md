# Radik — the task is more than the answer

**Capability, not authority.**

You ask an AI to explain a service agreement. It answers. Then you ask about an exception, switch to another company's terms, and come back. Later, a promise in one document changes. Eventually, you close the application.

What should remain when you return: a conversation to read again, or a task with its sources, results and unfinished work still connected?

**Radik is an interactive application built on the Radiolaria execution architecture.** It gives supported document tasks an identity, a working structure and memory. Models help interpret the request and produce candidate results. The runtime executes the admitted work and records what each result actually used. A model does not control its own authority.

This is a working development preview, not a proposed architecture waiting for its first execution. **Stage 4 is accepted** for the current document-work profile. Here is what happened in the recorded application runs.

[Explore the tasks](TRY_RADIK.md) · [Read the complete audit log](AUDIT_LOG.md) · [Check the evidence](VERIFY.md) · [Read with your AI assistant](READ_RADIK_STAGE04.xml)

<a id="scene-terms"></a>
## 1. The small print matters

The first service, **Fern**, offers priority telephone support to customers with an annual plan. There is a holiday exception. Urgent requests have a one-working-day response commitment. The price of calls is not stated.

These are fictional terms, but the application and model calls are real. Radik's recorded answer keeps the conditions separate. It does not turn “urgent requests” into “every request,” or a missing price into free calls:

> “The source does not specify call prices, so neither free calls nor any particular charge can be inferred.”

Now the owner focuses on the exception, then on the eligibility condition. **Both continuations execute native work without another model call.** One activates an additional audit step; the other skips that optional step because its condition is false. The runtime works with the accepted result instead of asking the model to reconstruct the same task.

A third continuation reaches the allowed revision limit. Radik stops that continuation and preserves the answer already obtained. Stopping further work does not mean throwing useful work away.

The owner moves to **Linden**, a different store, and asks whether a supplied statement matches three documents. The statement claims that opened sealed goods can be returned and the store always pays return postage. The recorded answer separates two problems: the first claim contradicts the returns rule; the second is not established because the payer is unspecified. It also distinguishes dispatch from arrival.

Then the owner selects Fern again. **The application uses Fern's saved material, not the more recent Linden answer.** It checks whether that material is still usable and consumes it through a new native memory step, with no new model call.

This is the P31 route. [Follow A1–A5 and B1–B2 in the audit log](AUDIT_LOG.md#p31-command-sequence), or inspect [the recorded answer](AUDIT_LOG.md#a1). Unlike Fern's single-document explanation (marked `SOURCE_BOUND_EXPLANATION`), the multi-document candidate checks for Linden and Moss carry the native flag `ENTAILMENT_REQUIRES_REVIEW`: verifying exact source byte spans and passing a finite semantic review does not turn the system into a universal truth oracle.

<a id="scene-change"></a>
## 2. One provider changes its promise

In a separate run, Radik compares **Alder** and **Birch**. Alder changes its response commitment from **one working day to three**. Birch changes nothing.

The important question is not whether the application can produce another answer. It is whether it can identify the work affected by the change and still use what remains valid.

Radik recomputes the affected branch. The unchanged native child is not put back in the queue. The new business result then uses the **exact earlier Birch extract** together with the updated Alder material. The record shows the input reaching its consumer, not just a label saying “cached.”

The new answer belongs to the new source revision. Its checks and acceptance are current. The earlier result remains history.

**Keep the work that is still useful. Recompute the work whose basis changed.** That is the observed P30 result. [Inspect the retained material and its new consumer](AUDIT_LOG.md#p30-source-change).

P30 used six model-role calls across its initial and changed-source work. This is not a zero-model recomputation claim, “half the cost,” or a measured speed advantage. P30 and P31 are separate runs.

<a id="scene-restart"></a>
## 3. Close the process. Keep the task, not its old authority

Back in P31, the owner gives Radik a new four-document task about **Moss**: check claims about dispatch, returns, postage and collection. Radik records its answer with the task, sources and conditions under which the result may be used.

Then process **62572 exits normally**. It is fully closed. A different process, **62857**, starts with empty controllers and a new operation.

The new process selects Moss and reads its exact saved result. It does not ask the model to generate the answer again. It checks the current conditions, obtains fresh local decisions and performs the memory-consuming work. **The original validity deadline is unchanged.** Reading an old result does not make it new.

The task's information survives. The previous process's live authority does not return merely because its records are on disk.

That distinction is central to Radik: **remembering what happened is not permission to do it again.** [Inspect the two processes, the unchanged clocks and the fresh checks](AUDIT_LOG.md#memory-and-process-restart).

This was a real close-and-reopen test, not a forced crash or a power-loss recovery test. Both processes exited normally. That is the result the evidence establishes.

## Where the model fits

The owner starts with an intention and sources. The model roles help choose a route and describe the work. Before the architect receives its task, the accepted context and constraints are fixed. The runtime owns the execution structure; native code performs the work; checks and the local Root make the corresponding acceptance decisions. **Root is the local decision boundary, not a more senior language model.**

Task memory keeps the result together with its sources and conditions. **Time-in-the-loop** means the application asks whether that result can be used *now*, not only whether it was once accepted. In the recorded returns to memory, the original acceptance and expiry times survive unchanged.

These relationships are what this application brings together from Radiolaria. [The Stage 4 dossier README](README.md#CH01) gives their exact names and boundaries. You do not need to learn every acronym before examining a task.

In the technical dossier and audit records, O/A/C names the three model roles: Orchestrator, Architect and Critic. U2 identifies bounded continuations of the same task; E identifies selective recomputation after a source change.

## Open the work, not just the claim

The [one-file audit log](AUDIT_LOG.md) follows all 20 P31 commands and the separately recorded P30 episodes. It links the request, the produced result, the next consumer and the relevant decisions. The [canonical index](claims_evidence.json) gives 94 evidence routes across 85 unique primary files, including SHA-256 identities and exact fields to inspect. Full verification uses the complete relative directory layout described in the [inspection guide](VERIFY.md#3-check-all-indexed-primary-files), not the index alone.

Read it yourself or open the [XML reader](READ_RADIK_STAGE04.xml) with your own AI assistant. Ask it to follow one task from the source text to the result, or to explain exactly what survived the process restart. [The inspection guide](VERIFY.md) separates reading the record, checking file identities and performing a fresh execution. A hash check is not a proof that an interpretation is true.

**Explore the implementation, try the supported tasks in the documented environment, and bring a counterexample.** A useful report identifies the source, the request, the observed result and the point where the behaviour differs from the stated rules. [Start exploring](TRY_RADIK.md).

## This preview and the larger architecture

The accepted scope is the current dynamic informational application profile: explanations, comparisons, supplied-statement checks, bounded continuations, qualified task memory and the recorded restart. These runs perform no SAVE or external action.

Radik is not being introduced as a network of banks, merchants or independent peers that anyone can already connect together. **Independent-owner exchange is Radik Stage 6; bounded capability acquisition is Stage 7; the connected minimal stand is Stage 8.** Stage 5 adds qualified experience and strategy. These are remaining application integrations, not claims that the corresponding reference mechanisms are absent from Radiolaria.

The [Radiolaria reference](https://github.com/AAkhtanin/hedgehog-os/tree/800f38c3407b3f4ec93dc943c977ffeecb614881) remains a separate project with its own cases and accepted scope. The [Stage 4 dossier README maps both numbering systems](README.md#two-maps-two-numbering-systems).

P30 took about **43 min 20 s** and P31 about **22 min 8 s** in the recorded environment. Those are different experiments, not a controlled performance comparison. Exact measurements and the known exceptional cleanup issue are visible in the [audit log](AUDIT_LOG.md#measurements), not omitted for presentation.

**Acceptance:** [Walker's 20 October 2026 handoff](WALKER_STAGE04_ACCEPTANCE_20261020.md). The recorded independent reviews are separate AI review passes, not external certification. This page tells the story of accepted records; it does not create telemetry, repeat the experiments or award a new acceptance.

Project author: **Andrey Akhtanin**. Engineering assistance: AI agents. Existing licenses and notices retain their own scope.
