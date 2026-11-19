# Cited Q&A over MITRE ATT&CK

> **Write-up:** `research.md` (coming once the project is complete) explains how it was built: tests, results, problems found and decisions. References like "research.md D29" point to its numbered entries.

RAG over MITRE ATT&CK Enterprise: a security analyst asks "what is this attack and how do I detect/mitigate it?" and gets an answer that cites ATT&CK IDs. See `RoadMAP.md` for the plan.

**Stage 1 scope:** Initial Access (TA0001) + Credential Access (TA0006).

## Data source (pinned)

| | |
|---|---|
| Source | [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data) |
| File | `enterprise-attack/enterprise-attack-20.1.json` |
| ATT&CK version | **20.1** |
| SHA-256 | `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # pulls in PyTorch: large, took >10 min
cp .env.example .env   # fill in keys when needed (not yet used in Stage 1 step 2)

mkdir -p data/raw/stix
curl -L -o data/raw/stix/enterprise-attack-20.1.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json
shasum -a 256 data/raw/stix/enterprise-attack-20.1.json   # must match the hash above
```

## Run

```bash
.venv/bin/python -I scripts/parse_stix.py       # step 2
.venv/bin/python -I scripts/build_passages.py   # step 3 (downloads BAAI/bge-small-en-v1.5 on first run)
.venv/bin/python -I scripts/embed_passages.py   # step 4
.venv/bin/python -I scripts/ask.py "How do attackers use spearphishing links, and how can I detect it?"   # step 5
```

Step 5 needs `ANTHROPIC_API_KEY` in `.env` (copy `.env.example`). Credentials can also come from an `ant auth login` profile instead of a key file. Retrieval and the "I don't know" checks run without any credentials.
- **Questions naming an ATT&CK ID** (e.g. `T1110.003`) are looked up by exact ID, because vector search can't tell IDs apart (`research.md` D25).
- **Otherwise the question is embedded and compared with two sets of vectors:** the 276 in-scope passages, and 616 "out-of-scope markers" (every other ATT&CK technique, used only to recognize topics this project doesn't cover).
- **The system answers "I don't have information on that." without calling Claude when:**
  - the best in-scope score is below **0.555** (off-topic, D29)
  - an out-of-scope marker beats the best in-scope passage by more than **0.02** (D32–D33)
  - the question names an ATT&CK or CVE ID that isn't loaded, or one that isn't a valid ID at all (ATT&CK: `T1234` or `T1234.567`, any case; D56)

## Stage 2: self-updating pipeline

```bash
.venv/bin/python -I scripts/run_pipeline.py            # one full run (what the scheduled job runs)
.venv/bin/python -I scripts/run_pipeline.py --offline  # skip the network checks
```

One run does the following:
1. **KEV:** fetches the CISA KEV catalog with an ETag check ("not modified" → nothing to do) and records only added / changed / removed CVEs.
2. **ATT&CK:** checks for a new ATT&CK release and appends it to the history.
3. **Rebuild:** rebuilds passages, then runs **dbt** (DuckDB models + 22 data tests). A failed test stops the run here, so bad data is never embedded (D59).
4. **Embed:** re-embeds only passages whose content fingerprint changed.
5. **Evaluate:** re-runs the free retrieval evaluation.
6. **Changelog:** adds an entry to `CHANGELOG.md`.

**Scheduled runs:** `.github/workflows/pipeline.yml` runs this on the 1st and 15th of each month and commits only the history files, the changelog and the eval results. `secret-scan.yml` scans every push for secrets.

History lives in small committed text files, so git stores only changed lines. Everything else is rebuilt on each run:

| File | Contents |
|---|---|
| `data/history/attack_history.csv` | Every technique in every ATT&CK Enterprise release (43 releases, v1.0–v20.1, 26,648 rows), backfilled once with `scripts/backfill_attack_history.py` |
| `data/history/attack_versions.csv` | One row per release |
| `data/history/kev_state.csv` | Current KEV catalog (one row per CVE) |
| `data/history/kev_meta.json` | ETag / Last-Modified from the last fetch |
| `data/history/kev_history.jsonl` | Append-only log of KEV changes |
| `CHANGELOG.md` | One readable entry per run |

The dbt project (`dbt/`) builds `attack_release_summary` (per-release counts of techniques added, changed, revoked, deprecated) and `attack_technique_changes` (what happened to each technique in each release). For example, v19.0 (April 2026) moved 198 techniques to new tactics when Defense Evasion was split into Stealth and Defense Impairment.

**Why a full rebuild instead of incremental models:** history is already append-only where the data comes in (ETag for KEV, `--append` for ATT&CK), and dbt rebuilds every table from those files in under a second. A rebuild keeps no hidden state between runs, so anyone who clones the repo gets the same warehouse. Incremental models would need the database to persist between scheduled runs; that's worth it only at a much larger size (`research.md` D42, D58). Staging models are views; the marts are tables.

**Search over two sources:** every question gets the top 5 **ATT&CK techniques** and, separately, up to 3 **known exploited vulnerabilities**. Mixing them in one ranking let CVEs crowd techniques out of the top 5 (`research.md` D45, D47). Exact IDs work for both, e.g. `T1110.003` or `CVE-2024-3400`.

## Stage 3: demo app

```bash
.venv/bin/streamlit run app/streamlit_app.py   # http://localhost:8501
```

Three pages:
- **Search:** live retrieval with the same "I don't know" checks as the evaluation. Example questions show AI answers pre-generated in the live run (`scripts/build_demo_examples.py`), so the public demo holds no API key.
- **Data pipeline:** ATT&CK release history, KEV updates, dbt test results and the changelog, read from the dbt marts.
- **Evaluation:** every metric below, read from `data/eval/` when the page loads.

## Evaluation (step 6)

```bash
.venv/bin/python -I scripts/evaluate.py                  # approved set: retrieval + gate, free, no API key
.venv/bin/python -I scripts/evaluate.py --set holdout    # held-out set, written after the settings were fixed
.venv/bin/python -I scripts/evaluate.py --claude         # also scores Claude's answers (needs API key)
```

Two test sets, both written in analyst language and mostly avoiding technique names:
- **Approved set** (`data/eval/test_set.json`, 33 answerable + 9 unanswerable): drafted with Claude, reviewed and approved by the project owner. The threshold and marker margin were tuned on it.
- **Held-out set** (`data/eval/holdout_set.json`, 50 + 50): written by Claude after those settings were fixed, not reviewed before running, and never used for tuning.

| Metric (ATT&CK 20.1, bge-small-en-v1.5) | Approved set | Held-out set |
|---|---|---|
| Top-5 retrieval accuracy | **31/33 (94%)** | **47/50 (94%)** |
| Correct technique ranked #1 | 28/33 | 42/50 |
| Answerable questions wrongly stopped | 2/33 | 2/50 |
| Unanswerable questions stopped before calling Claude | 7/9 | **37/50 (74%)** |
| Unanswerable questions declined overall (stopped, or answer says "not covered") | **9/9** | **50/50** |
| Unanswerable questions answered as if covered | **0/9** | **0/50** |

Live Claude Haiku run (`research.md` D52). "Declined" counts answers that open by saying the sources don't cover the question, even when they then offer related guidance; counting only plain declines, held-out is 41/50.

Held-out unanswerable questions by kind (after adding KEV and the both-lists stop rule, D47–D49; Stage 1 figures are in `research.md` D34):
- off-topic: 10/10 stopped
- ATT&CK techniques from tactics not loaded: 20/25
- unknown IDs: 5/5
- **security questions outside ATT&CK** (compliance, product how-tos): **2/10**, the main remaining gap. Those reach Claude, which must decline from the passages (`research.md` D34).

**KEV test set** (`data/eval/kev_test_set.json`: 20 answerable + 6 unanswerable, reviewed and approved by the project owner):
- the correct CVE is retrieved for **18/20**
- **0/20** real vulnerability questions are wrongly stopped. An out-of-scope topic must beat both the technique and the vulnerability lists before the system says "I don't know" (`research.md` D48–D49)

- **Per-question scores:** `data/eval/report.md`, `data/eval/holdout_report.md` and `data/eval/kev_report.md`, regenerated by `scripts/evaluate.py`.
- **How every number here was produced** (tests, outputs, problems, decisions): `research.md`.

## Answer quality and safety (live Claude Haiku run, `research.md` D52)

```bash
.venv/bin/python -I scripts/run_api_evals.py   # one session: --claude on all test sets, faithfulness, prompt injection
```

| Test | Result |
|---|---|
| **Faithfulness**: claims in answers supported by the cited passages (1,548 claims, 113 answers) | **89%** supported, 4 contradicted. 31% of answers fully supported; most gaps are added general advice beyond the sources |
| **Prompt injection**: a poisoned passage planted among the retrieved ones (6 attack types × 2 questions) | **0/12 attacks succeeded**; the answer flagged the injected instruction in 12/12 |
| Unanswerable questions answered as if covered (all 65 across three test sets) | **0/65** |

The faithfulness judge is the same model family as the answerer (cost choice), so 89% is likely an upper bound. Reports: `data/eval/faithfulness_report.md`, `data/eval/injection_report.md`. Estimated cost of the whole run: $0.34.

## Next improvements (measured, not yet done)

1. **Fewer unsupported additions:** most claims the faithfulness judge flagged were general advice beyond the sources ("reset the password"). Tighten the prompt and re-measure.
2. **Less over-cautious "partial" answers:** 12 answerable questions cited the right technique but were tagged "partial" because the question mentioned a detail the sources don't (e.g. "GPUs"). Tag partial only when the technique itself isn't identified.
3. **Check the judge:** hand-check a sample of the faithfulness judgments, or use a stronger, independent judge model.

## Contributing

Enable the secret-scanning pre-commit hook once per clone (requires `brew install gitleaks`):

```bash
git config core.hooksPath .githooks
```

- **Step 2** writes `data/processed/techniques.json`: one record per in-scope technique (90 for v20.1), with its tactics, description, detection strategies and mitigations joined on, and citation/markdown markup removed.
- **Step 3** writes `data/processed/passages.json`: 276 passages (description / detection / mitigations per technique), each at most 512 tokens with the bge tokenizer and each starting with its ATT&CK ID and name. Format: `research.md` D12.
- **Step 4** writes `data/processed/vectors.npy` (276 × 384, normalized float32), `data/processed/marker_vectors.npy` (616 out-of-scope markers, D33) and `data/processed/index.json` (model + revision, query instruction, passages and markers in row order). Storage choice: `research.md` D14.

Embedding model: `BAAI/bge-small-en-v1.5`, pinned to revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`.

## Attribution

This project uses data from MITRE ATT&CK®. © The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation, per the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
