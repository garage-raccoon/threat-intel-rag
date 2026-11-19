"""Copy owner-approved answers from the live API run into the demo's example file.

Usage: .venv/bin/python -I scripts/build_demo_examples.py
Reads  data/eval/{,holdout_,kev_}claude_results.json   (written by: evaluate.py --set <set> --claude)
Writes data/demo/examples.json

Answers are copied verbatim, never edited. Selection rule: tagged covered, cited an expected ID, and every
claim judged supported (faithfulness_results.json); plus one declined answer to show the app saying "not covered".
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from ask import CLAUDE_MODEL

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "data/eval"
INPUTS = ["claude_results.json", "holdout_claude_results.json", "kev_claude_results.json"]
OUT_PATH = ROOT / "data/demo/examples.json"
APPROVED = {  # eval question id -> short button label (order = display order)
    "A01": "Fake Microsoft login link",
    "A20": "LLMNR poisoning → NTLM hashes",
    "A30": "Forged SAML tokens",
    "A14": "Stolen session cookies",
    "H27": "Kubernetes secrets read",
    "H14": "One-time codes intercepted",
    "K03": "Kerberos KDC flaw → domain admin",
    "A31": "T1556.006",
    "K15": "CVE-2024-3400",
    "K16": "Log4Shell (CVE-2021-44228)",
    "HU13": "SOC 2 requirements (not covered)",
}


def main() -> None:
    rows, run_at = {}, {}
    for name in INPUTS:
        data = json.loads((EVAL_DIR / name).read_text(encoding="utf-8"))
        for r in data["rows"]:
            rows[r["id"]], run_at[r["id"]] = r, data["run_at"]
    missing = [i for i in APPROVED if i not in rows or not rows[i].get("answer")]
    if missing:
        sys.exit(f"No live answer for {missing}: rerun the --claude evals first")

    examples = [{"id": i, "label": label, "question": rows[i]["question"], "coverage": rows[i]["coverage"],
                 "answer": rows[i]["answer"], "model": CLAUDE_MODEL, "generated": run_at[i][:10],
                 "citations": [{"doc_id": c["doc_id"], "url": c["url"]} for c in rows[i]["citations"]]}
                for i, label in APPROVED.items()]
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"source": "live API eval run (the answers are copied, never edited)", "examples": examples}, indent=2),
                        encoding="utf-8")
    print(f"Wrote {len(examples)} examples to {OUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
