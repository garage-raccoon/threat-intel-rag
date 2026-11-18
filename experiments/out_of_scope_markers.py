"""Experiment X1 (research.md D31): two retrieval changes measured on the approved test set. Not part of the pipeline.

E1 "one passage per technique": rank techniques by their best passage, so one technique's 3 passages
   can't fill the top 5.
E2 "out-of-scope markers": also embed every ATT&CK technique OUTSIDE Stage 1 scope (description only).
   If the best match is one of those, the question is about a topic we don't cover -> answer "I don't know".
Usage: .venv/bin/python -I experiments/out_of_scope_markers.py
Writes experiments/out_of_scope_markers_rows.json; console output saved in experiments/out_of_scope_markers_output.txt.
"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ask  # noqa: E402
from parse_stix import attack_ref, clean, is_active  # noqa: E402

r = ask.Retriever()
P = r.index["passages"]
questions = json.loads((ROOT / "data/eval/test_set.json").read_text())["questions"]
in_scope = {p["attack_id"] for p in P}

# --- build out-of-scope marker passages from the same pinned STIX file
objs = json.loads((ROOT / "data/raw/stix/enterprise-attack-20.1.json").read_text())["objects"]
by_id = {o["id"]: o for o in objs}
parents = {o["source_ref"]: by_id[o["target_ref"]] for o in objs
           if o["type"] == "relationship" and o["relationship_type"] == "subtechnique-of" and is_active(o)}
tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic"}
markers = []
for o in objs:
    if o["type"] != "attack-pattern" or not is_active(o):
        continue
    tid = attack_ref(o)["external_id"]
    if tid in in_scope:
        continue
    parent = parents.get(o["id"])
    name = f"{parent['name']}: {o['name']}" if parent else o["name"]
    tactics = ", ".join(sorted(tactic_names[p["phase_name"]] for p in o.get("kill_chain_phases", [])
                               if p["kill_chain_name"] == "mitre-attack"))
    markers.append({"attack_id": tid, "tactics": tactics,
                    "text": f"{tid} {name} ({tactics}): Description\n{clean(o.get('description'))}"})
M = r.model.encode([m["text"] for m in markers], normalize_embeddings=True, batch_size=32)  # truncates at 512 tokens


def ranked_techniques(scores: np.ndarray) -> list[tuple[str, float]]:
    best = {}
    for i in np.argsort(-scores):
        best.setdefault(P[i]["attack_id"], float(scores[i]))
    return sorted(best.items(), key=lambda kv: -kv[1])


rows = []
for q in questions:
    passages, unknown = r.retrieve(q["question"])
    exact = passages[0]["match"] == "exact"
    v = r.model.encode(r.index["query_instruction"] + q["question"], normalize_embeddings=True)
    s_in, s_out = r.vectors @ v, M @ v
    base_ids = [p["attack_id"] for p in passages]
    tech = ranked_techniques(s_in)[:ask.TOP_K]
    dedup_ids = base_ids if exact else [t for t, _ in tech]
    best_in, j = float(s_in.max()), int(s_out.argmax())
    out_wins = (not exact) and float(s_out[j]) > best_in
    base_gate = ask.is_gated(passages, unknown)
    rows.append({
        "id": q["id"], "answerable": q["answerable"], "expected": q["expected"],
        "base_hit": any(e in base_ids for e in q["expected"]),
        "dedup_hit": any(e in dedup_ids for e in q["expected"]),
        "dedup_rank": next((i + 1 for i, t in enumerate(dedup_ids) if t in q["expected"]), None),
        "base_gated": base_gate, "e2_gated": base_gate or out_wins,
        "best_in": round(best_in, 3), "best_out": round(float(s_out[j]), 3),
        "margin": float(s_out[j]) - best_in, "best_out_id": markers[j]["attack_id"], "best_out_tactics": markers[j]["tactics"],
    })

A = [x for x in rows if x["answerable"]]
U = [x for x in rows if not x["answerable"]]
print(f"marker passages embedded: {len(markers)} out-of-scope techniques\n")
print(f"{'':34}{'baseline':>10}{'E1 dedup':>10}{'E2 markers':>12}{'E1+E2':>8}")
print(f"{'top-5 retrieval accuracy':34}{sum(x['base_hit'] for x in A):>7}/{len(A)}{sum(x['dedup_hit'] for x in A):>7}/{len(A)}"
      f"{sum(x['base_hit'] for x in A):>9}/{len(A)}{sum(x['dedup_hit'] for x in A):>5}/{len(A)}")
print(f"{'answerable wrongly gated':34}{sum(x['base_gated'] for x in A):>7}/{len(A)}{sum(x['base_gated'] for x in A):>7}/{len(A)}"
      f"{sum(x['e2_gated'] for x in A):>9}/{len(A)}{sum(x['e2_gated'] for x in A):>5}/{len(A)}")
print(f"{'unanswerable gated':34}{sum(x['base_gated'] for x in U):>8}/{len(U)}{sum(x['base_gated'] for x in U):>8}/{len(U)}"
      f"{sum(x['e2_gated'] for x in U):>10}/{len(U)}{sum(x['e2_gated'] for x in U):>6}/{len(U)}")
print("\nPer question (only rows where something changed or is interesting):")
for x in rows:
    changed = x["base_hit"] != x["dedup_hit"] or x["base_gated"] != x["e2_gated"] or not x["answerable"]
    if changed or x["id"] in ("A03", "A04"):
        print(f"  {x['id']:4} hit {x['base_hit']!s:5}->{x['dedup_hit']!s:5} rank(dedup)={x['dedup_rank']} | gated {x['base_gated']!s:5}->{x['e2_gated']!s:5}"
              f" | best in-scope {x['best_in']:.3f} vs out-of-scope {x['best_out']:.3f} {x['best_out_id']} ({x['best_out_tactics']})")
json.dump(rows, open(Path(__file__).with_name("out_of_scope_markers_rows.json"), "w"), indent=1)

print("\nMargin sweep: gate when (best out-of-scope - best in-scope) > m")
routed = [x for x in rows if x["id"] not in ("A31", "A32", "A33")]
for m in [0.0, 0.01, 0.02, 0.03, 0.05, 0.09]:
    ag = sum(1 for x in routed if x["answerable"] and (x["base_gated"] or x["margin"] > m))
    ug = sum(1 for x in routed if not x["answerable"] and (x["base_gated"] or x["margin"] > m))
    print(f"  m={m:.2f}  answerable wrongly gated {ag}/{len(A)}   unanswerable gated {ug}/{len(U)}")
