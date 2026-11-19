# Threat Intel RAG

A question-answering system for security analysts. Ask "how do attackers use spearphishing links, and how do I detect it?" and get an answer built only from **MITRE ATT&CK** (Initial Access and Credential Access) and the **CISA Known Exploited Vulnerabilities (KEV)** catalog, citing every source. When the sources don't cover a question, it says "I don't know" instead of guessing.

**Results, design decisions and open issues:** [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md)

| Held-out test set (written after the settings were fixed) | Result |
|---|---|
| Correct source found in the top 5 | 47/50 |
| Unanswerable questions answered as if covered | 0/50 |
| Claims in AI answers supported by the cited sources (all sets) | 89% |
| Prompt-injection attacks that succeeded | 0/12 |

## Stack

| Layer | Tools |
|---|---|
| Ingestion and scheduling | Python, GitHub Actions |
| Warehouse and transforms | DuckDB, dbt (models, data tests, unit test) |
| Search | `BAAI/bge-small-en-v1.5` embeddings, NumPy (no vector database: ~2.7k vectors fit in memory) |
| Answers | Claude Haiku (run once offline; the demo shows saved answers) |
| Demo | Streamlit, Altair |

## How it stays current

A GitHub Actions job runs on the **1st and 15th of each month**:
1. **KEV:** checks the feed with an ETag, so an unchanged catalog costs one request. Records added, changed and removed CVEs.
2. **ATT&CK:** checks for a new release and appends it to the history.
3. **Rebuild:** rebuilds the search passages, then runs the dbt models and tests. Tests guarding the search data stop the run; the rest warn.
4. **Embed:** re-embeds only passages whose content changed.
5. **Evaluate and log:** reruns the free search evaluation and writes an entry to [CHANGELOG.md](CHANGELOG.md).

History is committed as plain text in `data/history/`, so every change shows up in git. Everything else is rebuilt from it.

## Using the demo app

- **Search:** type a question or pick a ★ example. You see the matching ATT&CK techniques and KEV entries, or the reason the question was stopped. The ★ examples also show the AI answer saved from the live run.
- **Data pipeline:** how ATT&CK has changed across all 43 releases since 2018, recent KEV additions, the dbt test results and the latest changelog entries.
- **Evaluation:** every test result, read from `data/eval/` when the page loads.

The app never calls an AI model, and no API key exists anywhere in the deployed app.

## Run it locally

Requires Python 3.14.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt     # includes PyTorch: a large download
.venv/bin/streamlit run app/streamlit_app.py  # http://localhost:8501
```

On first start the app builds its data from `data/history/` (it downloads the latest ATT&CK release; about a minute). No API key is needed.

Optional:

```bash
.venv/bin/python -I scripts/run_pipeline.py --offline   # one pipeline run, without the network checks
.venv/bin/python -I scripts/evaluate.py --set holdout   # free search evaluation on the held-out set
.venv/bin/python -I scripts/ask.py "your question"      # a live AI answer: needs ANTHROPIC_API_KEY in .env
```

## Data sources

| Source | What's used | Pinned by |
|---|---|---|
| [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) (STIX) | Answers: Initial Access + Credential Access. History: all 43 releases (v1.0–v20.1) | Version and SHA-256 of every release, in `data/history/attack_versions.csv` |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | All entries | Catalog version and ETag, in `data/history/kev_meta.json` |
| Embedding model [`BAAI/bge-small-en-v1.5`](https://huggingface.co/BAAI/bge-small-en-v1.5) | Search | Revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a` |

## Repo structure

| Path | Contents |
|---|---|
| `app/` | Streamlit app: entry point and the three pages |
| `scripts/` | Pipeline steps (fetch, parse, build passages, embed), the scheduled run, question answering and evaluations |
| `dbt/` | Staging models over the history files, marts (release summary, technique changes, KEV runs), data and unit tests |
| `data/history/` | Committed history: ATT&CK releases and techniques, KEV state and change log |
| `data/eval/` | Test sets, results and per-question reports |
| `data/demo/` | AI answers saved from the live run, shown in the app |
| `experiments/` | One-off experiments that informed design choices |
| `.github/workflows/` | The scheduled pipeline and a secret scan on every push |
| `CHANGELOG.md` | One entry per pipeline run |
| `TECHNICAL_REPORT.md` | Results, design decisions, resolved and open issues |

## Attribution

This project uses data from MITRE ATT&CK®. © The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation, per the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
