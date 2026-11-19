"""Parse the pinned ATT&CK STIX bundle into one clean record per technique.

Usage: .venv/bin/python -I scripts/parse_stix.py [stix_path] [out_path]
Data (c) The MITRE Corporation, used under the ATT&CK terms of use.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
STIX_PATH = ROOT / "data/raw/stix/enterprise-attack-20.1.json"
OUT_PATH = ROOT / "data/processed/techniques.json"
TACTICS_IN_SCOPE = {"initial-access", "credential-access"}  # TA0001, TA0006

CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
CODE_TAG = re.compile(r"</?code>")


def clean(text: str) -> str:
    text = CITATION.sub("", text or "")
    text = MD_LINK.sub(r"\1", text)
    text = CODE_TAG.sub("", text)
    lines = (re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def attack_ref(obj: dict) -> dict:
    return next(r for r in obj["external_references"] if r.get("source_name") == "mitre-attack")


def is_active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse(objects: list[dict]) -> dict:
    by_id = {o["id"]: o for o in objects}
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objects if o["type"] == "x-mitre-tactic"}
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")

    # A mitigates-relationship carries its own technique-specific description; the
    # course-of-action description is generic, so prefer the relationship's text.
    mitigations, detections, parents = defaultdict(list), defaultdict(list), {}
    for rel in objects:
        if rel["type"] != "relationship" or not is_active(rel):
            continue
        src, tgt = by_id.get(rel["source_ref"]), by_id.get(rel["target_ref"])
        if not src or not tgt or not is_active(src):
            continue
        if rel["relationship_type"] == "subtechnique-of":
            parents[src["id"]] = tgt
        elif rel["relationship_type"] == "mitigates" and src["type"] == "course-of-action":
            mitigations[tgt["id"]].append({
                "id": attack_ref(src)["external_id"],
                "name": src["name"],
                "text": clean(rel.get("description") or src.get("description")),
            })
        elif rel["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
            analytics = [by_id[a] for a in src.get("x_mitre_analytic_refs", []) if a in by_id]
            detections[tgt["id"]].append({
                "id": attack_ref(src)["external_id"],
                "name": src["name"],
                "analytics": [
                    {"platforms": a.get("x_mitre_platforms", []), "text": clean(a.get("description"))}
                    for a in analytics
                ],
            })

    techniques, markers = [], []
    for obj in objects:
        if obj["type"] != "attack-pattern" or not is_active(obj):
            continue
        phases = {p["phase_name"] for p in obj.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"}
        ref = attack_ref(obj)
        parent = parents.get(obj["id"])
        if not phases & TACTICS_IN_SCOPE:
            # Out of scope: kept only as a marker, so retrieval can tell "not covered" apart.
            markers.append({
                "attack_id": ref["external_id"],
                "name": f"{parent['name']}: {obj['name']}" if parent else obj["name"],
                "tactics": sorted(tactic_names[p] for p in phases),
                "description": clean(obj.get("description")),
            })
            continue
        # STIX sub-technique names omit the parent ("Spearphishing Link"); the full name retrieves better.
        techniques.append({
            "attack_id": ref["external_id"],
            "name": f"{parent['name']}: {obj['name']}" if parent else obj["name"],
            "is_subtechnique": parent is not None,
            "parent_id": attack_ref(parent)["external_id"] if parent else None,
            "tactics": sorted(tactic_names[p] for p in phases),
            "platforms": obj.get("x_mitre_platforms", []),
            "description": clean(obj.get("description")),
            "detection_strategies": sorted(detections[obj["id"]], key=lambda d: d["id"]),
            "mitigations": sorted(mitigations[obj["id"]], key=lambda m: m["id"]),
            "url": ref["url"],
        })

    return {
        "source": "MITRE ATT&CK Enterprise (STIX 2.1), https://github.com/mitre-attack/attack-stix-data",
        "attack_version": collection["x_mitre_version"],
        "tactics_in_scope": sorted(tactic_names[t] for t in TACTICS_IN_SCOPE),
        "techniques": sorted(techniques, key=lambda t: t["attack_id"]),
        "out_of_scope_markers": sorted(markers, key=lambda m: m["attack_id"]),
    }


def main() -> None:
    stix_path = Path(sys.argv[1]) if len(sys.argv) > 1 else STIX_PATH
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else OUT_PATH
    result = parse(json.loads(stix_path.read_text(encoding="utf-8"))["objects"])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"ATT&CK {result['attack_version']}: wrote {len(result['techniques'])} techniques "
          f"+ {len(result['out_of_scope_markers'])} out-of-scope markers to {out_path}")


if __name__ == "__main__":
    main()
