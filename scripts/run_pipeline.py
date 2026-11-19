"""One scheduled pipeline run, end to end, then a CHANGELOG.md entry.

Usage: .venv/bin/python -I scripts/run_pipeline.py              # what the GitHub Actions job runs
       .venv/bin/python -I scripts/run_pipeline.py --offline    # skip network checks (KEV + new ATT&CK release)

Steps: KEV (ETag check, record changes) -> ATT&CK (new release? download + append to history) -> parse latest
release -> build passages -> dbt build (models + data tests) -> embed only changed passages -> free retrieval eval
on both test sets -> prepend a CHANGELOG.md section. Exits non-zero if any step or dbt test fails; a dbt failure stops
the run before embedding; other test failures are reported as warnings. The changelog entry is written either way, so a failed run is visible too.
"""
import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
HISTORY_DIR = ROOT / "data/history"
STIX_HISTORY_DIR = ROOT / "data/raw/stix/history"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
DBT_RESULTS_PATH = ROOT / "dbt/target/run_results.json"
WAREHOUSE_PATH = ROOT / "data/processed/warehouse.duckdb"
EVAL_RESULTS = {"approved set": ROOT / "data/eval/results.json", "held-out set": ROOT / "data/eval/holdout_results.json"}
RELEASES_API = "https://api.github.com/repos/mitre-attack/attack-stix-data/contents/enterprise-attack"
RELEASE_FILE = re.compile(r"enterprise-attack-(\d+(?:\.\d+)*)\.json$")
TIMEOUT_S = 120
MAX_LISTED = 12  # changelog lists at most this many new CVEs by name


def run(args: list[str], step: str, log: list[str]) -> str:
    """Run one step; on failure record it and raise so the run stops (the changelog is still written)."""
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    out = proc.stdout.strip()
    if proc.returncode != 0:
        log.append(f"**{step} FAILED** (exit {proc.returncode}): {(proc.stderr or out).strip().splitlines()[-1:]}")
        raise RuntimeError(step)
    return out


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def known_versions() -> list[str]:
    with (HISTORY_DIR / "attack_versions.csv").open(newline="", encoding="utf-8") as f:
        return sorted((r["version"] for r in csv.DictReader(f)), key=version_key)


def check_attack_releases(offline: bool, log: list[str]) -> list[str]:
    """Download any ATT&CK release newer than the history, append it, and return the new versions."""
    if offline:
        return []
    listing = requests.get(RELEASES_API, timeout=TIMEOUT_S, headers={"User-Agent": "attack-rag-pipeline/0.1"})
    listing.raise_for_status()
    remote = {m.group(1): f["download_url"] for f in listing.json() if (m := RELEASE_FILE.search(f["name"]))}
    new = sorted(set(remote) - set(known_versions()), key=version_key)
    STIX_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    for v in new:
        resp = requests.get(remote[v], timeout=TIMEOUT_S)
        resp.raise_for_status()
        (STIX_HISTORY_DIR / f"enterprise-attack-{v}.json").write_bytes(resp.content)
    if new:
        run([PY, "-I", "scripts/backfill_attack_history.py", "--append"], "ATT&CK history append", log)
    return new


def latest_release_file(offline: bool) -> Path:
    """The newest known release must be on disk to rebuild passages (a fresh checkout won't have it)."""
    v = known_versions()[-1]
    path = STIX_HISTORY_DIR / f"enterprise-attack-{v}.json"
    if not path.exists() and not offline:
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/{path.name}"
        resp = requests.get(url, timeout=TIMEOUT_S)
        resp.raise_for_status()
        STIX_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        path.write_bytes(resp.content)
    return path


def kev_section(run_at: str) -> str:
    meta = json.loads((HISTORY_DIR / "kev_meta.json").read_text())
    result = meta.get("last_result")
    if result == "not_modified":
        return f"- **KEV:** not modified since the last fetch (ETag unchanged); {meta.get('count')} entries"
    if result == "baseline":
        return f"- **KEV:** baseline load, {meta.get('count')} entries (catalog {meta.get('catalog_version')})"
    lines = [json.loads(l) for l in (HISTORY_DIR / "kev_history.jsonl").read_text().splitlines() if l.strip()]
    this_run = [l for l in lines if l["run_at"] == meta["last_checked"]]
    added = [l for l in this_run if l["change"] == "added"]
    text = (f"- **KEV** (catalog {meta.get('catalog_version')}, {meta.get('count')} entries): "
            f"{result['added']} added, {result['changed']} changed, {result['removed']} removed")
    for a in added[:MAX_LISTED]:
        text += f"\n  - {a['cveID']}: {a['vulnerabilityName']} (added {a['dateAdded']})"  # name already has vendor + product
    if len(added) > MAX_LISTED:
        text += f"\n  - … and {len(added) - MAX_LISTED} more (see `data/history/kev_history.jsonl`)"
    return text


def attack_section(new_versions: list[str]) -> str:
    latest = known_versions()[-1]
    if not new_versions:
        return f"- **ATT&CK:** no new release (latest {latest}; {len(known_versions())} releases in history)"
    import duckdb  # only needed when there is something to summarize
    con = duckdb.connect(str(WAREHOUSE_PATH), read_only=True)
    rows = con.execute("SELECT version, added, changed, revoked, deprecated, dropped FROM attack_release_summary "
                       f"WHERE version IN ({','.join('?' * len(new_versions))})", new_versions).fetchall()
    return "\n".join(f"- **ATT&CK {v}** (new release): {a} added, {c} changed, {r} revoked, {d} deprecated, {x} dropped"
                     for v, a, c, r, d, x in rows)


def dbt_section(proc: subprocess.CompletedProcess) -> str:
    if not DBT_RESULTS_PATH.exists():  # deleted before the run, so a missing file means dbt never got to run nodes
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:]
        return f"- **dbt FAILED** before building anything (e.g. a SQL compile error): {detail}"
    results = json.loads(DBT_RESULTS_PATH.read_text())["results"]
    tests = [r for r in results if r["unique_id"].startswith("test.")]
    name = lambda r: r["unique_id"].split(".")[2]
    warned = [name(r) for r in results if r["status"] == "warn"]  # data problems that don't stop the run
    failed = [name(r) for r in results if r["status"] not in ("pass", "success", "warn")]
    models = sum(r["unique_id"].startswith("model.") and r["status"] == "success" for r in results)
    return (f"- **dbt:** {models} models built, {sum(r['status'] == 'pass' for r in tests)}/{len(tests)} data tests "
            "passed" + (f"; WARNING: {', '.join(warned)}" if warned else "")
            + (f"; FAILED or skipped: {', '.join(failed)}" if failed else ""))


def eval_summaries() -> dict[str, dict]:
    return {name: json.loads(p.read_text())["summary"] for name, p in EVAL_RESULTS.items() if p.exists()}


def eval_section(before: dict, after: dict) -> str:
    parts = []
    for name, s in after.items():
        b = before.get(name, {})
        delta = lambda k: "" if b.get(k) == s[k] else f" (was {b.get(k, 'n/a')})"
        parts.append(f"{name}: top-5 {s['top5_retrieval_accuracy']}{delta('top5_retrieval_accuracy')}, "
                     f"unanswerable stopped {s['unanswerable_gated']}{delta('unanswerable_gated')}, "
                     f"answerable wrongly stopped {s['answerable_wrongly_gated']}{delta('answerable_wrongly_gated')}")
    return "- **Search eval** (free, no API): " + "; ".join(parts)


def write_changelog(run_at: str, items: list[str], ok: bool) -> None:
    header = "# Changelog\n\nOne entry per pipeline run (newest first), written by `scripts/run_pipeline.py`.\n"
    old = CHANGELOG_PATH.read_text(encoding="utf-8") if CHANGELOG_PATH.exists() else header
    body = old[len(header):] if old.startswith(header) else old
    entry = f"\n## {run_at[:10]} run ({run_at[11:16]} UTC){'' if ok else ' FAILED'}\n" + "\n".join(items) + "\n"
    CHANGELOG_PATH.write_text(header + entry + body, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="skip the KEV fetch and the ATT&CK release check")
    args = parser.parse_args()

    run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    items: list[str] = []
    before = eval_summaries()
    ok = True
    try:
        if not args.offline:
            run([PY, "-I", "scripts/fetch_kev.py"], "KEV fetch", items)
        items.append(kev_section(run_at))
        new_versions = check_attack_releases(args.offline, items)
        run([PY, "-I", "scripts/parse_stix.py", str(latest_release_file(args.offline))], "parse ATT&CK", items)
        run([PY, "-I", "scripts/build_passages.py"], "build passages", items)
        DBT_RESULTS_PATH.unlink(missing_ok=True)  # so a stale file from an earlier run is never reported
        proc = subprocess.run([str(Path(PY).with_name("dbt")), "build", "--project-dir", "dbt", "--profiles-dir", "dbt",
                               "--quiet"], cwd=ROOT, capture_output=True, text=True)
        items.append(dbt_section(proc))
        if proc.returncode != 0:  # a failed data test means bad data: don't embed or evaluate it
            items.append("- **Stopped:** embedding and search eval skipped because dbt failed")
            raise RuntimeError("dbt build")
        items.insert(-1, attack_section(new_versions))
        emb = run([PY, "-I", "scripts/embed_passages.py"], "embed", items)
        items.append(f"- **Embeddings:** {emb.splitlines()[-1].split(' -> ')[0]}")
        for set_name in ("main", "holdout"):
            run([PY, "-I", "scripts/evaluate.py", "--set", set_name], f"eval {set_name}", items)
        items.append(eval_section(before, eval_summaries()))
    except (RuntimeError, requests.RequestException) as e:
        ok = False
        if isinstance(e, requests.RequestException):
            items.append(f"**Network step FAILED:** {e}")
    write_changelog(run_at, items, ok)
    print("\n".join(items))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
