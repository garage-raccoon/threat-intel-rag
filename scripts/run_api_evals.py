"""The one live-API session (research.md D50-D51): --claude evals on all three test sets, then faithfulness, then
prompt injection. Stops before spending anything if the credentials don't work.

Usage: .venv/bin/python -I scripts/run_api_evals.py
Credentials: ANTHROPIC_API_KEY in .env, or an `ant auth login` profile (the SDK picks either up).
"""
import json
import subprocess
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from ask import CLAUDE_MODEL

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
STEPS = [["scripts/evaluate.py", "--set", s, "--claude"] for s in ("main", "holdout", "kev")] + \
        [["scripts/eval_faithfulness.py"], ["scripts/eval_injection.py"]]
COST_FILES = ["data/eval/claude_results.json", "data/eval/holdout_claude_results.json",
              "data/eval/kev_claude_results.json", "data/eval/faithfulness_results.json", "data/eval/injection_results.json"]


def main() -> None:
    load_dotenv(ROOT / ".env")
    try:  # preflight: proves the credentials and model work before any paid call (listing a model is not billed)
        anthropic.Anthropic().models.retrieve(CLAUDE_MODEL)
    except anthropic.AuthenticationError:
        sys.exit("No working credentials: add ANTHROPIC_API_KEY to .env, or run `ant auth login`. Nothing was spent.")
    except anthropic.NotFoundError:
        sys.exit(f"Model {CLAUDE_MODEL} isn't available to this account. Nothing was spent.")
    for step in STEPS:
        print(f"\n=== {' '.join(step)}", flush=True)
        if subprocess.run([PY, "-I", *step], cwd=ROOT).returncode != 0:
            sys.exit(f"Step failed: {' '.join(step)} (earlier steps' results are saved)")
    total = sum(json.loads((ROOT / f).read_text())["summary"].get("est_cost_usd", 0) for f in COST_FILES)
    print(f"\nAll done. Estimated total cost: ${total:.2f} (list prices; check the Console for the billed amount)")


if __name__ == "__main__":
    main()
