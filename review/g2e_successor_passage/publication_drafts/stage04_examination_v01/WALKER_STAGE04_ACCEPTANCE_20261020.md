# Radik Stage04: Walker acceptance and publication handoff

Review date: 2026-10-20.

## Decision

**ACCEPTED: Stage04 is closed within the current dynamic informational application profile.**

The basis is the accepted P30 selective-E execution, the P31 ordinary owner scenario, and applicable unchanged prior controls. This decision does not accept Stages05-08, a general external-effect profile, or the complete minimal stand.

## Exact reviewed return

- File: `RADIK_RETURN_20261020T153800.320838Z.tar.gz`
- SHA-256: `3173a01a69f3ac98fe11dd17a8d0af5b4ea62d024c29a70811613ec6b461fcf3`
- Compressed bytes: 9,440,653.
- Archive: 521 regular members; 520 content entries plus `manifest.json`.
- All content sizes and hashes match the manifest. No missing or extra files were found.
- All 94 dossier evidence paths resolve inside the extracted return; byte lengths, hashes and indexed JSON pointers were checked successfully.
- The XML parses successfully and its content IDs are unique.

The archive manifest's packaging-only classification is intentional. Runtime acceptance comes from the actual evidence and its reviews, not from the act of packaging.

## Actual acceptance basis

P31 owner run: `OWNER_20261020T135920_1936851b33af4ae2aeaef4ead90cbb34`.

Application source identity: `ea4a2dc46ddb9ca24b92c10c2c1d968471b0247e155d24249e60796eab9adfe0`.

Reference P: commit `800f38c3407b3f4ec93dc943c977ffeecb614881`, tree `d665994930e50c7f10d5f928d57ceb7aac758203`. Application extensions remain separately attributed.

The review read the original receipt, scenario and all 20 command readbacks, with primary accounting, continuation and memory records. It confirmed:

- 1,327.948490167 seconds; 20 commands; nine completed role calls and nine closed rounds.
- Console accounting progresses from 35 to 44 with its historical prefix preserved.
- Processes 62572 and 62857 both exited with code 0 and were reaped; the restart preserves the original shared deadline and binds the first process's closure.
- A2 performs its audit; A3 and B2 skip their optional audit according to the guard.
- A4 reaches the expected revision exhaustion without new model calls and preserves A3's result.
- Cancellation prevents subsequent dispatch before a new grant and preserves the accepted result.
- A5 consumes A's qualified memory. R2 consumes C's saved material in a new process with fresh checks, unchanged original validity times and no model fallback.
- C is a new four-source task with predecessor B.
- All ten current coverage rows corresponding to S4-01 through S4-09, including split subrows, are accepted. P30 selective E is credited separately; P31 executes no E and no SAVE.

Authoritative reviewed records are under `evidence/review/g2e_successor_passage/p31_actual_acceptance/`, especially `independent_actual_acceptance_review.json`, `stage04_composite_acceptance.json`, `identity_accounting_review.json`, `native_consumer_review.json` and `memory_control_restart_review.json`.

This review used file reading, integrity checks and separate AI review passes. It did not import or execute archived application code, repeat native computation, call a provider, change authentication, or perform SAVE. It is not external certification.

## Reader files

The separately supplied `READ_RADIK_STAGE04.xml`, `README.md`, `README.ru.md` and `claims_evidence.json` are exact byte copies of the accepted dossier members at:

`evidence/review/g2e_successor_passage/publication_drafts/stage04_examination_v01/`

The XML is the compact explanatory entry. The JSON supplies 11 claims, 94 evidence routes, the scenario, coverage and 21 deferred directions. Full raw-evidence navigation requires the original archive layout; detached files do not recreate its parent directories.

## Retained limits

The finite fictional-document exercise does not establish external truth or arbitrary-task competence. Model identity levels and retained UNKNOWN fields remain distinct. Reference Gates and Radik Stages remain separate. Historical STOPPED records and synthetic/source evidence retain their original classifications.

`MAINT-P31-CLEANUP-STOP-NS` remains open and nonblocking: in the documented exceptional unreaped-child branch, nominal cleanup may reach 40 seconds instead of 30. The successful normal exits do not test or repair that branch.

## Stop point and publication plan

The supplied `RADIK_GITHUB_PUBLICATION_PLAN_20261020_RU(1).md` has been read and is consistent with the agreed handoff: preserve the accepted source layout and history, use a separate proposed `AAkhtanin/radiolaria-radik` repository, inspect the exact private snapshot, and require a separate owner decision before making that same repository public. Repository existence, local Git state and GitHub authorization still require verification during the authorized publication passage.

No repository creation, commit, push, visibility change, release or Stage05 work is performed by this acceptance.

The owner's language policy is now explicit: future repository additions and newly authored repository text are English-only, with no new Cyrillic text. Russian conversation and owner handoff instructions stay outside repository publication. Existing Russian material in this accepted return is preserved; no cleanup, translation refactor or alteration of immutable historical evidence is authorized here.

**Next decision: the owner and curator arrange the GitHub publication passage. Stage05 remains paused.**
