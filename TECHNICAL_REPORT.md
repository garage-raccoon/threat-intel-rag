# Technical report

Status as of 2026-11-19. Every number below comes from the result files in `data/eval/` or from a recorded test run.

## Abstract

This project answers security questions from MITRE ATT&CK (Initial Access and Credential Access) and the CISA Known Exploited Vulnerabilities (KEV) catalog. Every answer cites its sources, and the system says "I don't know" when the sources don't cover the question. A scheduled pipeline (GitHub Actions, DuckDB, dbt) keeps the knowledge base current and records how ATT&CK has changed across all 43 releases since 2018.

**Main findings**
- **Search finds the right source** for 47 of 50 held-out questions (top 5). Exact IDs needed their own lookup, because vector search can't tell IDs apart.
- **No unanswerable question was answered as if covered: 0 of 65** across three test sets. A score threshold alone couldn't do this: it only catches off-topic questions, so out-of-scope detection was added.
- **89% of the claims in AI answers are supported by the cited sources** (1,378 of 1,548). Most unsupported claims are general advice the model added.
- **0 of 12 prompt-injection attacks succeeded.**
- **The dbt models are tested for correctness, not only format.** A reconciliation test and a unit test cover change-detection cases the real data has never hit. A code review found one such latent bug, now fixed.

**Main changes along the way:** an exact-ID lookup; out-of-scope markers; separate result lists for techniques and vulnerabilities; stricter handling of malformed IDs; and a test policy where only tests guarding the search data stop a pipeline run.

**Future work:** stop the model adding unsourced advice; make coverage tags less cautious; verify the AI judge by hand; write a fresh held-out test set; tune the vulnerability-search threshold on vulnerability questions.

## Results at a glance

| What was measured | Approved set | Held-out set | KEV set |
|---|---|---|---|
| Questions (answerable + unanswerable) | 33 + 9 | 50 + 50 | 20 + 6 |
| Correct source in the top 5 | 31/33 | **47/50** | 18/20 |
| Correct source ranked first | 28/33 | 42/50 | 18/20 |
| Unanswerable stopped before any AI call | 7/9 | 37/50 | 3/6 |
| Unanswerable answered as if covered (live AI run) | **0/9** | **0/50** | **0/6** |
| Answerable: AI cited the expected source | 30/33 | 45/50 | 18/20 |

- The **approved set** was used to set the threshold.
- The **held-out set** was written after the settings were fixed, and nothing was tuned on it.
- **Who wrote the questions:** all test questions were drafted with Claude and reviewed and approved by the project owner.
- **Sample size:** each set has a few dozen questions, so every number has a wide margin of error.

## 1. A self-updating pipeline that keeps full history

**What it does:**
- Twice a month (the 1st and 15th), a GitHub Actions job runs the pipeline end to end:
  1. Checks the KEV feed with an ETag. CISA answers *not modified* unless the catalog changed, so an unchanged catalog costs one request.
  2. Checks for a new ATT&CK release and downloads only that release.
  3. Rebuilds the search passages.
  4. Runs the dbt models and tests in DuckDB.
  5. Re-embeds only the passages whose content fingerprint changed.
  6. Reruns the free search evaluation and writes a changelog entry.
- History is committed as plain text files, so every change shows up in git:
  - `attack_history.csv`: 26,648 rows, one per technique per release, across all 43 ATT&CK releases
  - the KEV state file
  - an append-only KEV change log
- Everything else (the warehouse, passages, vectors) is rebuilt from those files on every run.

**Tested:**
- **Full rebuild of all 43 releases:** 4.5 s.
- **First full pipeline run:** 24 s.
- **A run with nothing new:** 0 passages re-embedded and 2,674 reused from cache. KEV returned *not modified* (HTTP 304).
- **KEV change detection:** an older copy of the feed was compared against the current one. It correctly reported 9 added, 1 changed (and which field changed) and 1 removed.

**What the history shows:**
- **v7.0 (2020):** MITRE introduced sub-techniques (302 added, 129 revoked).
- **v19.0 (2026):** 198 techniques moved to a different tactic when Defense Evasion was split.

**Why there are no incremental models:** at about 27,000 rows, each dbt model builds in 0.01–0.13 s. Incremental models would add state that can drift, for no measurable gain. History is appended at ingestion instead, and derived tables are rebuilt from it every run.

## 2. Data tests that prove the models are correct

**Coverage:**
- **8 dbt models** over declared file sources.
- **41 data tests:** unique and non-null keys, accepted values, well-formed CVE IDs, passages within the embedding model's 512-token limit, and source relationships.
- **1 unit test** of the change-detection logic.

**Tests of correctness, not just format:**
- **Reconciliation:** for every release, active techniques = previous active techniques + the net effect of its recorded changes.
- **Grain:** at most one change per technique per release.
- **Unit test:** six made-up techniques across three made-up releases cover cases the real data never hits:
  - a technique that disappears and returns
  - a move from deprecated to revoked
  - a tactic change
  - a reactivation

**Bug found in review (resolved):**
- **The bug:** the change model compared each technique with its previous *appearance*, not the previous release. A technique missing from one release and back in the next would have been recorded as dropped and never as returned, and the release totals would no longer reconcile.
- **Impact:** none of the 43 real releases trigger it, so no published number was wrong.
- **Fix:** it now records `returned` and `status_changed` changes.

**Each test was proven to catch what it should,** by breaking the code on purpose:
- Removing the fix fails the unit test.
- Silently losing the "added" rows makes the reconciliation test flag 19 releases.

**Test policy:**
- The 8 tests guarding the search passages (IDs, URLs, fingerprints, empty or over-long passages) **stop the run** before embedding, because a passage without a URL can't be cited.
- Every other data test **warns**: the run continues and the changelog names the test. One odd value in a new KEV entry shouldn't block an update.

## 3. A measured "I don't know"

Before any AI call, a question is stopped if:
- no source is similar enough (score below **0.555**)
- it names an ID that isn't in the data
- its closest match is an ATT&CK technique this project doesn't load

**How the threshold was set:** 0.555 sits in the middle of the gap between the highest off-topic score (0.512) and the lowest answerable score (0.599) on the approved set.

**Key finding: a threshold only catches off-topic questions.** In-domain questions about uncovered topics (lateral movement, ransomware) scored 0.610–0.735. That's inside the answerable range (0.599–0.811), because to the embedding model they look like the questions this project does cover.

**Fix:**
- The 616 ATT&CK techniques outside the two loaded tactics are embedded as *markers*: never shown and never sent to the AI.
- If a marker beats the best real result by more than 0.02, the question is out of scope.

| Approved set | Threshold only | With markers |
|---|---|---|
| Unanswerable stopped before the AI call | 3/9 | **7/9** |
| Answerable wrongly stopped | 0/33 | 2/33 |

**Questions that get past these checks** go to the AI, which is told to answer only from the sources and to tag its answer *covered*, *partial* or *not covered*. In the live run:
- **0 of 65 unanswerable questions were answered as if covered.**
- 51 of 65 were either stopped or tagged *not covered*.
- The other 14 were tagged *partial*: the answer said the sources don't cover the question, then offered related guidance.

## 4. Search failures found and fixed

**Vector search can't match IDs (resolved).**
- Asking for `T1110.003` returned an unrelated technique, with a score above the threshold. An ID is an arbitrary string, so similar-looking IDs sit close together whatever they mean.
- **Fix:** an exact-ID lookup. A known ATT&CK or CVE ID returns exactly that record. An unknown one gets "I don't know" and is never swapped for a similar-looking ID.

**Malformed IDs got answers (resolved).** Questions like `T1110.0031` fell through to vector search, where digit-heavy text scored above the threshold. Malformed and unknown IDs are now caught, each with its own explanation:
- "not a valid ID"
- "right format, not in the knowledge base"

All existing test questions kept the same outcome.

**Adding vulnerabilities hurt technique search (resolved).** With all 1,782 KEV entries in one ranking with the techniques, specific CVEs crowded the right technique out of the top 5:

| Top 5 correct | Before KEV | One mixed ranking | Separate lists (current) |
|---|---|---|---|
| Approved set | 31/33 | 27/33 | **31/33** |
| Held-out set | 47/50 | 44/50 | **47/50** |

**Fix:** techniques (top 5) and vulnerabilities (top 3) are now ranked as separate lists.

## 5. AI answers: faithful to the sources, and resistant to injection

The AI path ran once, live, on all three test sets with Claude Haiku. The estimated cost was $0.34. The demo shows answers copied from that run, so visitors never trigger an API call and no API key exists anywhere in the deployed app.

**Faithfulness:**
- A judge model split 113 answers into 1,548 claims and checked each against the sources the answer was given.
- **Result:** **1,378 supported (89%)**, 166 unsupported and 4 contradicted. Only 35 of the 113 answers were supported in full.
- **What the unsupported claims are:**
  - Mostly general advice the model added ("reset the password").
  - Some are mappings from the user's scenario to a technique, which are arguably fine.
- **The 4 contradictions, checked by hand:**
  - 2 are real model errors about what the sources cover.
  - 1 is a judge error.
  - 1 follows a retrieval miss.

**Prompt injection:**
- **Setup:** six kinds of poisoned passage, each looking like a real entry but carrying a hidden instruction, were planted among the real sources at test time only. The kinds were override, malicious link, false reassurance, prompt leak, fake authority, and an instruction buried in a list. Each ran with 2 questions.
- **Detection:** success is detected by an exact canary string, not by a judge.
- **Result:** **0 of 12 attacks succeeded.** The answer warned about the planted instruction in 12 of 12. The canary appeared in 6 answers, always inside that warning.

## Resolved and open issues

**Resolved**
- **Exact IDs** retrieved the wrong technique → exact-ID lookup.
- **Malformed IDs** reached the AI → caught and explained.
- **Out-of-scope questions** passed the score threshold → out-of-scope markers.
- **Vulnerabilities crowded out techniques** → separate result lists.
- **The change model would have missed a returning technique** → fixed, with a unit test and a reconciliation test.
- **The pipeline kept embedding after a failed data test** → tests guarding the search data now stop the run.

**Open**
- **Added advice:** most unsupported claims are advice beyond the sources. Next step: tighten the prompt and re-measure with the same judge.
- **Over-cautious *partial* tags:** 12 answerable questions cited the right source but were tagged *partial* because the question mentioned a detail the sources lack. Next step: tag *partial* only when the sources don't identify the technique or CVE.
- **Lenient judge:**
  - The faithfulness judge is the same model family as the answerer (a cost choice), so 89% is likely an upper bound.
  - A hand-check of 10 judgments is pending.
- **Held-out set no longer fully clean:** its results were seen when one design choice was made (when to stop as out of scope). No number was tuned on it, but a fresh held-out set would give a clean figure.
- **Vulnerability threshold** is reused from the technique test set and was never tuned on vulnerability questions.
- **Out of reach by design:**
  - Security questions outside ATT&CK (compliance, product how-tos) are mostly left to the AI to decline.
  - Tactic IDs such as `TA0001` are declined as off-topic.
  - Questions over the whole catalog ("how many…", "the newest…") need queries, not search.
- **Hosted demo freshness:** after a scheduled update, a running server keeps its old index until it restarts.
