"""Stage 2, step 1: reduce every ATT&CK Enterprise release to a technique-by-version table.

Usage: .venv/bin/python -I scripts/backfill_attack_history.py            # full rebuild from every raw release
       .venv/bin/python -I scripts/backfill_attack_history.py --append   # add only releases not in the CSV yet
(--append is what scheduled runs use: they only download the new release, not all 1.36 GB.)
Reads  data/raw/stix/history/enterprise-attack-<version>.json (all releases, downloaded once, not committed)
Writes data/history/attack_history.csv  (one row per technique per release: committed, research.md D41-D42)
       data/history/attack_versions.csv (one row per release)
Re-running is safe: output is rebuilt from the raw files and sorted, so unchanged input gives identical files.
"""
import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from parse_stix import attack_ref, clean  # same cleaning as the live pipeline

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
STIX_HISTORY_DIR = ROOT / "data/raw/stix/history"
HISTORY_DIR = ROOT / "data/history"
FILE_PATTERN = re.compile(r"enterprise-attack-(\d+(?:\.\d+)*)\.json$")
HISTORY_FIELDS = ["version", "attack_id", "name", "is_subtechnique", "tactics", "platforms", "status",
                  "content_hash", "stix_modified"]
VERSION_FIELDS = ["version", "approx_release_date", "techniques_active", "techniques_revoked",
                  "techniques_deprecated", "file_sha256"]


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in version.split("."))


def status_of(obj: dict) -> str:
    if obj.get("revoked"):
        return "revoked"
    return "deprecated" if obj.get("x_mitre_deprecated") else "active"


def content_hash(name: str, tactics: str, platforms: str, description: str) -> str:
    """Fingerprint of what a reader sees; changes when the name, tactics, platforms or description change."""
    return hashlib.sha256("\x1f".join([name, tactics, platforms, description]).encode()).hexdigest()[:16]


def reduce_release(version: str, objects: list[dict]) -> list[dict]:
    by_id = {o["id"]: o for o in objects}
    parents = {o["source_ref"]: by_id.get(o["target_ref"]) for o in objects
               if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of"
               and not o.get("revoked")}
    rows: dict[str, dict] = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        try:
            attack_id = attack_ref(obj)["external_id"]
        except StopIteration:  # a few objects carry no mitre-attack reference
            continue
        parent = parents.get(obj["id"])
        name = f"{parent['name']}: {obj.get('name', '')}" if parent else obj.get("name", "")
        # Tactic short codes, not display names: v1.0 has no tactic objects to name them, and a code only changes
        # when MITRE really reorganizes (defense-evasion -> stealth in v20), so renamed labels don't count as changes.
        tactics = ";".join(sorted(p["phase_name"] for p in obj.get("kill_chain_phases", [])
                                  if p.get("kill_chain_name") == "mitre-attack"))
        platforms = ";".join(sorted(obj.get("x_mitre_platforms", [])))
        description = clean(obj.get("description", ""))
        row = {"version": version, "attack_id": attack_id, "name": name,
               "is_subtechnique": str(bool(obj.get("x_mitre_is_subtechnique", parent is not None))).lower(),
               "tactics": tactics, "platforms": platforms, "status": status_of(obj),
               "content_hash": content_hash(name, tactics, platforms, description),
               "stix_modified": obj.get("modified", "")}
        # An ID can appear twice in one release (an old revoked object next to its replacement): keep the active one.
        if attack_id not in rows or (rows[attack_id]["status"] != "active" and row["status"] == "active"):
            rows[attack_id] = row
    return sorted(rows.values(), key=lambda r: r["attack_id"])


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append", action="store_true", help="keep existing rows; process only new releases")
    parser.add_argument("--stix-dir", type=Path, default=STIX_HISTORY_DIR)
    args = parser.parse_args()
    stix_dir = args.stix_dir
    files = sorted(((m.group(1), p) for p in stix_dir.glob("enterprise-attack-*.json")
                    if (m := FILE_PATTERN.search(p.name))), key=lambda vp: version_key(vp[0]))
    if not files:
        sys.exit(f"No enterprise-attack-<version>.json files in {stix_dir}")

    history, versions = [], []
    if args.append:
        history = read_csv(HISTORY_DIR / "attack_history.csv")
        versions = read_csv(HISTORY_DIR / "attack_versions.csv")
        done = {v["version"] for v in versions}
        files = [(v, p) for v, p in files if v not in done]
        if not files:
            print("No new ATT&CK releases to add")
            return
    for version, path in files:
        raw = path.read_bytes()
        rows = reduce_release(version, json.loads(raw)["objects"])
        history += rows
        count = lambda s: sum(r["status"] == s for r in rows)
        versions.append({"version": version,
                         "approx_release_date": max(r["stix_modified"] for r in rows)[:10],  # newest edit in the release
                         "techniques_active": count("active"), "techniques_revoked": count("revoked"),
                         "techniques_deprecated": count("deprecated"), "file_sha256": hashlib.sha256(raw).hexdigest()})
        print(f"{version:>5}  {len(rows):4} techniques  ({count('active')} active)")

    history.sort(key=lambda r: (version_key(r["version"]), r["attack_id"]))
    versions.sort(key=lambda r: version_key(r["version"]))
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    for path, fields, data in [(HISTORY_DIR / "attack_history.csv", HISTORY_FIELDS, history),
                               (HISTORY_DIR / "attack_versions.csv", VERSION_FIELDS, versions)]:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(data)
    print(f"\nprocessed {len(files)} release(s); {len(versions)} releases, {len(history)} rows -> "
          f"{HISTORY_DIR.relative_to(ROOT)}/attack_history.csv")


if __name__ == "__main__":
    main()
