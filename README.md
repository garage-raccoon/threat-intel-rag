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

Step 5 needs `ANTHROPIC_API_KEY` in `.env` (copy `.env.example`). **Note:** the project owner chose not to use an API key, so the live Claude call in `ask.py` has not been run. Retrieval and the "I don't know" checks run without a key, and the answer step was evaluated with a blind Haiku stand-in (`research.md` D38, D40).
- **Questions naming an ATT&CK ID** (e.g. `T1110.003`) are looked up by exact ID, because vector search can't tell IDs apart (`research.md` D25).
- **Otherwise the question is embedded and compared with two sets of vectors:** the 276 in-scope passages, and 616 "out-of-scope markers" (every other ATT&CK technique, used only to recognize topics this project doesn't cover).
- **The system answers "I don't have information on that." without calling Claude when:**
  - the best in-scope score is below **0.555** (off-topic, D29)
  - an out-of-scope marker beats the best in-scope passage by more than **0.02** (D32–D33)
  - the question names an ATT&CK ID that isn't loaded

## Stage 2: self-updating pipeline

```bash
.venv/bin/python -I scripts/run_pipeline.py            # one full run (what the scheduled job runs)
.venv/bin/python -I scripts/run_pipeline.py --offline  # skip the network checks
```

One run does the following:
1. **KEV:** fetches the CISA KEV catalog with an ETag check ("not modified" → nothing to do) and records only added / changed / removed CVEs.
2. **ATT&CK:** checks for a new ATT&CK release and appends it to the history.
3. **Rebuild:** rebuilds passages, then runs **dbt** (DuckDB models + 22 data tests).
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

**Search over two sources:** every question gets the top 5 **ATT&CK techniques** and, separately, up to 3 **known exploited vulnerabilities**. Mixing them in one ranking let CVEs crowd techniques out of the top 5 (`research.md` D45, D47). Exact IDs work for both, e.g. `T1110.003` or `CVE-2024-3400`.

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
| Unanswerable questions stopped before calling Claude | 7/9 | **40/50 (80%)** |
| Unanswerable questions answered "I don't know" overall* | 9/9 | **43/50 (86%)** strict; 50/50 counting "not covered, but related:" answers |

\* The answer-model step was measured with a blind Haiku stand-in (`experiments/blind_haiku_eval/`, `research.md` D38), not the production API call. Of 12 unanswerable questions that got past retrieval, Haiku gave **0 confident answers**: 5 plain declines, 7 "the passages don't cover this" plus related material. It answered all 6 answerable control questions correctly.

Held-out unanswerable questions by kind:
- off-topic: 10/10 stopped
- ATT&CK techniques from tactics not loaded: 22/25
- unknown IDs: 5/5
- **security questions outside ATT&CK** (compliance, product how-tos): **3/10**, the main remaining gap. Those reach Claude, which must decline from the passages (`research.md` D34).

**KEV test set** (`data/eval/kev_test_set.json`: 20 answerable + 6 unanswerable, reviewed and approved by the project owner):
- the correct CVE is retrieved for **18/20**
- **3/20** real vulnerability questions are wrongly stopped, because the "I don't know" checks look at the technique list only (`research.md` D48)

- **Per-question scores:** `data/eval/report.md`, `data/eval/holdout_report.md` and `data/eval/kev_report.md`, regenerated by `scripts/evaluate.py`.
- **How every number here was produced** (tests, outputs, problems, decisions): `research.md`.

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
