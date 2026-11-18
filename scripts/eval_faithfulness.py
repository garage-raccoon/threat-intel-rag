"""Answer faithfulness: does each claim in Claude's answer follow from the passages it was given? (research.md D51)

Usage: .venv/bin/python -I scripts/eval_faithfulness.py
Reads  data/eval/{,holdout_,kev_}claude_results.json   (written by: evaluate.py --set <set> --claude)
Writes data/eval/faithfulness_results.json and faithfulness_report.md

A judge model splits each answer into atomic claims and labels each one against the passages that were sent:
supported | unsupported (not in the passages) | contradicted | meta (statements about coverage, e.g.
"the passages don't describe X", which aren't factual claims about the topic). Judge = the same Haiku model as
the answerer, by the owner's choice: a model grading its own family's output is likely lenient, so the score is an
upper bound and 10 judgments are sampled for a human check.
"""
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from ask import CLAUDE_MODEL, INDEX_PATH

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "data/eval"
INPUTS = ["claude_results.json", "holdout_claude_results.json", "kev_claude_results.json"]
RESULTS_PATH = EVAL_DIR / "faithfulness_results.json"
REPORT_PATH = EVAL_DIR / "faithfulness_report.md"
JUDGE_MODEL = CLAUDE_MODEL  # owner's choice (D51): Haiku for answering and judging
HAIKU_USD_PER_MTOK = (0.10, 0.50)  # Claude API reference, cached 2026-11-03
SAMPLE_FOR_HUMAN_CHECK = 10
JUDGE_SYSTEM = (
    "You check whether an answer is faithful to source passages. Split the ANSWER into atomic factual claims "
    "(one fact each; ignore citation markers like [1]). For each claim, decide using ONLY the PASSAGES:\n"
    "- supported: the passages state it or it follows directly from them\n"
    "- unsupported: the passages don't contain it (even if it is true in the real world)\n"
    "- contradicted: the passages say otherwise\n"
    "- meta: a statement about what the passages do or don't cover, not a claim about the topic\n"
    "Quote the shortest passage text that supports or contradicts the claim as evidence (empty if none)."
)
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {"claims": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "claim": {"type": "string"},
            "verdict": {"type": "string", "enum": ["supported", "unsupported", "contradicted", "meta"]},
            "evidence_passage_id": {"type": "string"},
            "evidence_quote": {"type": "string"},
        },
        "required": ["claim", "verdict", "evidence_passage_id", "evidence_quote"],
        "additionalProperties": False,
    }}},
    "required": ["claims"],
    "additionalProperties": False,
}


def judge(client: anthropic.Anthropic, answer: str, passages: list[dict]) -> tuple[list[dict], dict]:
    sources = "\n\n".join(f"<passage id=\"{p['passage_id']}\">\n{p['text']}\n</passage>" for p in passages)
    response = client.messages.create(
        model=JUDGE_MODEL,
        max_tokens=16000,
        output_config={"effort": "medium", "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}},
        system=JUDGE_SYSTEM,
        messages=[{"role": "user", "content": f"PASSAGES:\n{sources}\n\nANSWER:\n{answer}"}],
    )
    usage = response.usage.to_dict()
    if response.stop_reason == "refusal":
        return [{"claim": "(judge refused)", "verdict": "judge_refused", "evidence_passage_id": "", "evidence_quote": ""}], usage
    text = next(b.text for b in response.content if b.type == "text")  # json_schema format: first text block is JSON
    return json.loads(text)["claims"], usage


def main() -> None:
    load_dotenv(ROOT / ".env")
    passages = {p["passage_id"]: p for p in json.loads(INDEX_PATH.read_text(encoding="utf-8"))["passages"]}
    rows = []
    for name in INPUTS:
        path = EVAL_DIR / name
        if not path.exists():
            sys.exit(f"Missing {path.relative_to(ROOT)}: run evaluate.py --claude for that set first")
        for r in json.loads(path.read_text())["rows"]:
            if r.get("coverage") in ("covered", "partial") and r.get("answer"):
                rows.append({"set": name.removesuffix("claude_results.json").rstrip("_") or "approved", **r})

    client = anthropic.Anthropic()
    tin = tout = 0
    for n, r in enumerate(rows, 1):
        try:
            r["claims"], usage = judge(client, r["answer"], [passages[i] for i in r["sent_passages"]])
        except anthropic.AuthenticationError:
            sys.exit("Claude API rejected the credentials (see README: .env key or `ant auth login`)")
        except (anthropic.RateLimitError, anthropic.APIStatusError, anthropic.APIConnectionError) as e:
            r["claims"], usage = [], {"input_tokens": 0, "output_tokens": 0}
            r["judge_error"] = f"{type(e).__name__}: {e}"
        tin, tout = tin + usage["input_tokens"], tout + usage["output_tokens"]
        print(f"  [{n}/{len(rows)}] {r['id']}: {len(r['claims'])} claims")

    scored = lambda r: [c for c in r["claims"] if c["verdict"] in ("supported", "unsupported", "contradicted")]
    claims = [c for r in rows for c in scored(r)]
    count = lambda v: sum(c["verdict"] == v for c in claims)
    answers_ok = [r for r in rows if scored(r) and all(c["verdict"] == "supported" for c in scored(r))]
    summary = {
        "judge_model": JUDGE_MODEL, "answers_judged": len(rows),
        "claims_scored": len(claims),
        "claims_supported": f"{count('supported')}/{len(claims)}",
        "claims_unsupported": count("unsupported"), "claims_contradicted": count("contradicted"),
        "answers_fully_supported": f"{len(answers_ok)}/{sum(1 for r in rows if scored(r))}",
        "judge_errors": sum(1 for r in rows if r.get("judge_error")),
        "tokens_in_out": f"{tin} / {tout}",
        "est_cost_usd": round(tin * HAIKU_USD_PER_MTOK[0] / 1e6 + tout * HAIKU_USD_PER_MTOK[1] / 1e6, 4),
    }
    sample = random.Random(20261118).sample([(r["id"], c) for r in rows for c in scored(r)], min(SAMPLE_FOR_HUMAN_CHECK, len(claims)))
    RESULTS_PATH.write_text(json.dumps({"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                        "summary": summary, "rows": rows, "human_check_sample": sample}, indent=2))

    cell = lambda s: " ".join((s or "").split()).replace("|", "\\|")
    bad = [(r["id"], c) for r in rows for c in scored(r) if c["verdict"] != "supported"]
    lines = ["# Answer faithfulness report", "",
             f"Generated by `scripts/eval_faithfulness.py`. Judge: `{JUDGE_MODEL}` (same family as the answering model, "
             "so likely lenient: treat as an upper bound).", "",
             "| Metric | Result |", "|---|---|", *[f"| {k} | {v} |" for k, v in summary.items()], "",
             "## Claims not supported by the passages", "", "| Question | Verdict | Claim | Evidence |", "|---|---|---|---|",
             *[f"| {i} | {c['verdict']} | {cell(c['claim'])} | {cell(c['evidence_quote'])} |" for i, c in bad], "",
             f"## Human check: {len(sample)} random judgments (mark agree / disagree)", "",
             "| Question | Judge said | Claim | Evidence quoted | Agree? |", "|---|---|---|---|---|",
             *[f"| {i} | {c['verdict']} | {cell(c['claim'])} | {cell(c['evidence_quote'])} | |" for i, c in sample], ""]
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    for k, v in summary.items():
        print(f"{k:26} {v}")
    print(f"\nWrote {RESULTS_PATH.relative_to(ROOT)} and {REPORT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
