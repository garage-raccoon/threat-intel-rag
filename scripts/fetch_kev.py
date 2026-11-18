"""Stage 2, step 2: fetch the CISA KEV catalog and record only what changed since the last run.

Usage: .venv/bin/python -I scripts/fetch_kev.py              # live feed, with an ETag check
       .venv/bin/python -I scripts/fetch_kev.py --input F    # use a local copy of the feed (testing)
State (committed, research.md D42):
  data/history/kev_state.csv     current catalog, one row per CVE, sorted (git stores only changed lines)
  data/history/kev_meta.json     ETag / Last-Modified / catalog version from the last fetch
  data/history/kev_history.jsonl append-only log: one line per added / changed / removed CVE per run
Exit code 0 in all normal cases (including "not modified"); non-zero only on a failed download.
"""
import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
HISTORY_DIR = ROOT / "data/history"
STATE_PATH = HISTORY_DIR / "kev_state.csv"
META_PATH = HISTORY_DIR / "kev_meta.json"
LOG_PATH = HISTORY_DIR / "kev_history.jsonl"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT_S = 60
FIELDS = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
          "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes"]


def normalize(entry: dict) -> dict:
    row = {f: entry.get(f, "") for f in FIELDS}
    row["cwes"] = ";".join(entry.get("cwes") or [])
    row = {k: " ".join(str(v).split()) for k, v in row.items()}  # collapse whitespace so cosmetic edits don't count
    row["row_hash"] = hashlib.sha256("\x1f".join(row[f] for f in FIELDS).encode()).hexdigest()[:16]
    return row


def read_state() -> dict[str, dict]:
    if not STATE_PATH.exists():
        return {}
    with STATE_PATH.open(newline="", encoding="utf-8") as f:
        return {r["cveID"]: r for r in csv.DictReader(f)}


def write_state(rows: dict[str, dict]) -> None:
    with STATE_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS + ["row_hash"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows[k] for k in sorted(rows))


def fetch(meta: dict) -> tuple[dict | None, dict]:
    """(feed or None if not modified, response headers worth keeping)."""
    headers = {"User-Agent": "attack-rag-pipeline/0.1"}
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]
    resp = requests.get(KEV_URL, headers=headers, timeout=TIMEOUT_S)
    kept = {"etag": resp.headers.get("ETag", meta.get("etag")),
            "last_modified": resp.headers.get("Last-Modified", meta.get("last_modified"))}
    if resp.status_code == 304:
        return None, kept
    resp.raise_for_status()
    return resp.json(), kept


def diff(old: dict[str, dict], new: dict[str, dict]) -> list[dict]:
    changes = [{"change": "added", "cveID": c, "dateAdded": new[c]["dateAdded"], "vendorProject": new[c]["vendorProject"],
                "product": new[c]["product"], "vulnerabilityName": new[c]["vulnerabilityName"]}
               for c in sorted(new.keys() - old.keys())]
    changes += [{"change": "changed", "cveID": c,
                 "fields": [f for f in FIELDS if old[c].get(f) != new[c].get(f)]}
                for c in sorted(new.keys() & old.keys()) if old[c]["row_hash"] != new[c]["row_hash"]]
    changes += [{"change": "removed", "cveID": c} for c in sorted(old.keys() - new.keys())]
    return changes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, help="read the feed from a local JSON file instead of downloading")
    args = parser.parse_args()

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if args.input:
        feed, kept = json.loads(args.input.read_text(encoding="utf-8")), {k: meta.get(k) for k in ("etag", "last_modified")}
    else:
        try:
            feed, kept = fetch(meta)
        except requests.RequestException as e:
            sys.exit(f"KEV download failed: {e}")

    if feed is None:
        META_PATH.write_text(json.dumps({**meta, **kept, "last_checked": run_at, "last_result": "not_modified"}, indent=2) + "\n")
        print(f"KEV: not modified since last fetch (ETag {kept['etag']}); nothing to do")
        return

    old = read_state()
    new = {e["cveID"]: normalize(e) for e in feed["vulnerabilities"]}
    is_baseline = not old
    changes = [] if is_baseline else diff(old, new)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        lines = ([{"change": "baseline", "count": len(new)}] if is_baseline else changes)
        for c in lines:
            f.write(json.dumps({"run_at": run_at, "catalog_version": feed.get("catalogVersion"), **c}) + "\n")
    write_state(new)
    counts = {k: sum(c["change"] == k for c in changes) for k in ("added", "changed", "removed")}
    META_PATH.write_text(json.dumps({**kept, "catalog_version": feed.get("catalogVersion"),
                                     "date_released": feed.get("dateReleased"), "count": len(new),
                                     "last_checked": run_at, "last_result": "baseline" if is_baseline else counts},
                                    indent=2) + "\n")
    if is_baseline:
        print(f"KEV baseline: {len(new)} entries, catalog {feed.get('catalogVersion')}")
    else:
        print(f"KEV {feed.get('catalogVersion')}: {counts['added']} added, {counts['changed']} changed, "
              f"{counts['removed']} removed ({len(new)} total)")


if __name__ == "__main__":
    main()
