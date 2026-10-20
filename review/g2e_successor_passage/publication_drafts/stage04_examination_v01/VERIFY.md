# Inspect saved Stage 4 evidence

[Start here](START_HERE.md) · [One-file audit log](AUDIT_LOG.md) · [Accepted dossier](README.md)

## Begin without an account or a live run

Read the recorded walkthrough and [existing XML](READ_RADIK_STAGE04.xml). Open [claims_evidence.json](claims_evidence.json) when a claim needs its exact path, hash or selector. These are saved data. They do not call a model, recreate a Host, perform Work, restore an old grant or create a SAVE.

This publication has two different completeness levels:

| Material | What it supports |
| --- | --- |
| Detached README, XML and index | Understanding the reported run and checking the index/reader agree |
| The complete accepted RETURN or a correctly staged repository snapshot | Reading and checking all indexed primary files |

The five detached files supplied to the publication editor do **not** contain the 85 distinct primary files behind the 94 routes. Walker's acceptance reports that they were checked in the complete RETURN. A missing raw file is a missing input, not permission to manufacture a substitute.

## 1. Identify the accepted archive

The independent Walker handoff identifies:

```text
RADIK_RETURN_20261020T153800.320838Z.tar.gz
9440653 bytes
SHA-256 3173a01a69f3ac98fe11dd17a8d0af5b4ea62d024c29a70811613ec6b461fcf3
521 regular members: 520 content entries plus manifest.json
```

The checksum is taken from the separately supplied [acceptance handoff](WALKER_STAGE04_ACCEPTANCE_20261020.md#exact-reviewed-return), not calculated from the archive and then accepted as its own expected value. An expected digest is only as trustworthy as its source.

For example, in the directory containing the delivered archive on macOS:

```sh
shasum -a 256 RADIK_RETURN_20261020T153800.320838Z.tar.gz
```

Compare the output to the expected value above. Keep the original RETURN and its original manifest unchanged. This presentation does not repack it or create another runtime signing system.

## 2. Check the exact reader and index

Requirements: Python 3.10 or later, standard library only. No project installation, provider credentials or network access. From the repository root:

```sh
python3 -B review/g2e_successor_passage/publication_drafts/stage04_examination_v01/inspect_stage04.py
```

The helper verifies pinned SHA-256 identities for the index and XML, parses them as inert data, and checks the route IDs, 20 command outcomes, role counters, accepted coverage and reported measurements.

Expected successful result:

```text
INDEX_AND_READER_CONSISTENT
primary_evidence_verified: false
```

That result deliberately does **not** claim to have checked primary evidence. This mode also works with detached inputs using `--index /path/claims_evidence.json --xml /path/READ_RADIK_STAGE04.xml`.

## 3. Check all indexed primary files

The repository publisher must preserve the existing dossier and parent directories. The complete archive stores them under `evidence/review/...`; the ordinary project routes are `review/...`. Preserve the relationship between the dossier and its siblings. Do not flatten the archive or rewrite the accepted index to suit a different layout.

On a complete project snapshot, from the repository root:

```sh
python3 -B review/g2e_successor_passage/publication_drafts/stage04_examination_v01/inspect_stage04.py \
  --verify-evidence --root .
```

On the extracted RETURN, select its dossier explicitly; the helper itself can remain in a separate documentation directory:

```sh
python3 -B /path/to/inspect_stage04.py \
  --index /path/to/extracted-return/evidence/review/g2e_successor_passage/publication_drafts/stage04_examination_v01/claims_evidence.json \
  --xml /path/to/extracted-return/evidence/review/g2e_successor_passage/publication_drafts/stage04_examination_v01/READ_RADIK_STAGE04.xml \
  --verify-evidence --root /path/to/extracted-return
```

The paths in this second command are examples to replace with the actual extraction location; they are not original historical runtime commands.

A full successful result is:

```text
INDEXED_EVIDENCE_BYTES_AND_SELECTORS_MATCH
primary_evidence_verified: true
94 evidence routes
85 distinct primary files
93 JSON pointers resolved
1 source-file selector with its line ranges present
```

The source-file range check confirms that the stated lines exist in the exact file; it does not evaluate the meaning of the code. The helper reads data and prints a JSON result to standard output. It does not execute archived code or write into the project. Missing files, mismatched hashes, missing selectors, path escapes and symlink routes fail with a nonzero exit code. There is no fallback to regenerated evidence.

## What the helper does not establish

This is a documentation-side integrity and navigation check, **not full native replay**. It does not verify cryptographic signatures, repeat P30 E, reproduce model responses, prove external truth or award Stage 4 acceptance again. The authoritative accepted conclusions remain in the original actual reviews and [Walker's handoff](WALKER_STAGE04_ACCEPTANCE_20261020.md).

The application source identity `ea4a2dc46ddb9ca24b92c10c2c1d968471b0247e155d24249e60796eab9adfe0` is separate from a future publication commit. The reference basis is `800f38c3407b3f4ec93dc943c977ffeecb614881`; separately attributed application extensions are not relabelled as unchanged reference bytes.

## A fresh execution is a different operation

This page is a **first inspection**, not a new one-command installation or live test. A fresh application run requires the current supported environment, provider access where applicable, and new current admissions. Do not replay the consumed P30/P31 owner commands or recover authority from old JSON. The publisher should retain the project's existing current launch instructions without inventing new flags or a universal clean-install claim.

In particular, the recorded process restart is a normal close-and-reopen test. It is not a host reboot, an unplanned crash campaign or evidence that the known exception-cleanup issue was repaired.

## Why the reading surface is separate

The accepted dossier and raw records remain unchanged. `START_HERE.md` explains the experiment, `AUDIT_LOG.md` renders its trajectory, this file describes how to inspect it, and the existing JSON/XML remain the precise reference. That separation follows the documentation disciplines of [GitHub README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes), [Google Technical Writing](https://developers.google.com/tech-writing/one/documents), [Diataxis](https://diataxis.fr/) and the artifact/description separation in [SWE-bench experiments](https://github.com/SWE-bench/experiments). None of these references certifies Radik or places this experiment in that benchmark.
