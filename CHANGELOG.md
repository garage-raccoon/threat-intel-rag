# Changelog

One entry per pipeline run (newest first), written by `scripts/run_pipeline.py`.

## 2026-11-19 run (10:20 UTC)
- **KEV** (catalog 2026.11.18, 1786 entries): 4 added, 0 changed, 0 removed
  - CVE-2024-10441: Synology DiskStation Manager (DSM) Improper Encoding or Escaping of Output Vulnerability (added 2026-11-18)
  - CVE-2026-40217: BerriAI LiteLLM Unprotected Alternate Channel Vulnerability (added 2026-11-18)
  - CVE-2026-90436: Apache Axis Unsafe Reflection Vulnerability (added 2026-11-18)
  - CVE-2026-90817: Vanderbilt University Research Electronic Data Capture (REDCap) Code Injection Vulnerability (added 2026-11-18)
- **ATT&CK:** no new release (latest 20.1; 43 releases in history)
- **dbt:** 8 models built, 41/41 data tests passed
- **Embeddings:** 2062 passages + 616 markers: embedded 2678 new/changed, reused 0 from cache
- **Search eval** (free, no API): approved set: top-5 31/33, unanswerable stopped 7/9, answerable wrongly stopped 2/33; held-out set: top-5 47/50, unanswerable stopped 37/50, answerable wrongly stopped 2/50

## 2026-11-18 run (03:31 UTC)
- **KEV:** not modified since the last fetch (ETag unchanged); 1782 entries
- **ATT&CK:** no new release (latest 20.1; 43 releases in history)
- **dbt:** 8 models built, 22/22 data tests passed
- **Embeddings:** 2058 passages + 616 markers: embedded 0 new/changed, reused 2674 from cache
- **Search eval** (free, no API): approved set: top-5 31/33, unanswerable stopped 7/9, answerable wrongly stopped 2/33; held-out set: top-5 47/50, unanswerable stopped 39/50, answerable wrongly stopped 2/50
