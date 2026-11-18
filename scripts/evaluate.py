"""Stage 1, step 6: score retrieval and the "I don't know" gate against a test set.

Usage:
  .venv/bin/python -I scripts/evaluate.py                  # approved set (D26): retrieval + gate, free, no API key
  .venv/bin/python -I scripts/evaluate.py --set holdout    # held-out set (D34), written after settings were fixed
  .venv/bin/python -I scripts/evaluate.py --claude         # also calls Claude for questions that pass the gate
Writes data/eval/<prefix>results.json (machine-readable) and data/eval/<prefix>report.md (per-question table).
See research.md D26+.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from ask import CLAUDE_MODEL, MARKER_MARGIN, THRESHOLD, TOP_K, Retriever, answer, gate_reason

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "data/eval"
TEST_SETS = {  # name -> (test set file, output prefix)
    "main": ("test_set.json", ""),
    "holdout": ("holdout_set.json", "holdout_"),
}
# claude-haiku-5-5 list price per million input / output tokens (Claude API reference, cached 2026-11-03).
# Used only for the cost estimate printed after a --claude run.
HAIKU_USD_PER_MTOK = (0.10, 0.50)


def score_retrieval(questions: list[dict], retriever: Retriever) -> list[dict]:
    rows = []
    for q in questions:
        r = retriever.retrieve(q["question"])
        found = [p["attack_id"] for p in r.passages]
        reason = gate_reason(r)
        rows.append({
            "id": q["id"], "question": q["question"], "kind": q["kind"], "answerable": q["answerable"],
            "expected": q["expected"],
            "retrieved": [[p["attack_id"], round(p["score"], 3)] for p in r.passages],
            "hit": any(e in found for e in q["expected"]),
            "rank": next((i + 1 for i, a in enumerate(found) if a in q["expected"]), None),
            "match": r.passages[0]["match"], "top_score": round(r.passages[0]["score"], 4),
            "top_attack_id": r.passages[0]["attack_id"], "unknown_ids": r.unknown_ids,
            "marker_id": r.marker["attack_id"] if r.marker else None,
            "marker_tactics": r.marker["tactics"] if r.marker else None,
            "marker_score": round(r.marker["score"], 4) if r.marker else None,
            "gated": reason is not None, "gate_reason": reason,
        })
    return rows


def best_threshold(rows: list[dict]) -> dict:
    """Threshold that best separates answerable from unanswerable among vector-routed questions.

    Exact-ID and unknown-ID questions are decided by the ID check, not the score, so they're excluded.
    Ties are broken by the widest gap, and the threshold is placed mid-gap.
    """
    routed = [r for r in rows if r["match"] == "vector" and not r["unknown_ids"]]
    scores = sorted({r["top_score"] for r in routed})
    best = None
    for t in [(a + b) / 2 for a, b in zip(scores, scores[1:])]:
        correct = sum((r["top_score"] >= t) == r["answerable"] for r in routed)
        gap = min(s for s in scores if s >= t) - max(s for s in scores if s < t)
        if best is None or (correct, gap) > best[0]:
            best = ((correct, gap), t)
    (correct, gap), t = best
    return {"threshold": round(t, 3), "correct": correct, "of": len(routed), "gap": round(gap, 4)}


def score_claude(questions: list[dict], rows: list[dict], retriever: Retriever) -> None:
    """Call Claude for every question that passes the gate and record its own coverage judgment (D39).

    Scored on Claude's COVERAGE tag, not on citations: a "not covered, but related:" answer still cites
    passages (D38 showed the old citations-based rule undercounted declines).
    """
    client = anthropic.Anthropic()
    todo = [(q, r) for q, r in zip(questions, rows) if not r["gated"]]
    for n, (q, r) in enumerate(todo, 1):
        try:
            res = answer(q["question"], retriever, client)
        except anthropic.AuthenticationError:
            sys.exit("Claude API rejected the credentials: set ANTHROPIC_API_KEY in .env (nothing was written)")
        except (anthropic.RateLimitError, anthropic.APIStatusError, anthropic.APIConnectionError) as e:
            r.update(claude="error", coverage=None, error=f"{type(e).__name__}: {e}")
            print(f"  [{n}/{len(todo)}] {r['id']}: {type(e).__name__}")
            continue
        r.update(claude=res["status"], coverage=res.get("coverage"), answer=res.get("answer"),
                 cited_ids=sorted({c["attack_id"] for c in res.get("citations", [])}),
                 refusal_category=res.get("refusal_category"),
                 input_tokens=res["usage"]["input_tokens"], output_tokens=res["usage"]["output_tokens"])
        print(f"  [{n}/{len(todo)}] {r['id']}: {r['claude']} / coverage {r['coverage']}")
    for r in rows:
        if r["gated"]:
            r["claude"] = "skipped (gated)"


def summarize_claude(rows: list[dict]) -> dict:
    ans = [r for r in rows if r["answerable"]]
    una = [r for r in rows if not r["answerable"]]
    called = [r for r in rows if r.get("claude") not in (None, "skipped (gated)")]
    count = lambda rs, cond: f"{sum(1 for r in rs if cond(r))}/{len(rs)}"
    tin, tout = sum(r.get("input_tokens", 0) for r in called), sum(r.get("output_tokens", 0) for r in called)
    return {
        "claude_model": CLAUDE_MODEL,
        "claude_calls": len(called),
        # D38/D39: "partial" (says it's not covered first, then offers related guidance) counts as declining.
        "unanswerable_declined": count(una, lambda r: r["gated"] or r.get("coverage") in ("partial", "not_covered")),
        "unanswerable_declined_strict": count(una, lambda r: r["gated"] or r.get("coverage") == "not_covered"),
        "unanswerable_answered_as_covered": count(una, lambda r: r.get("coverage") == "covered"),
        "answerable_correct": count(ans, lambda r: not r["gated"] and r.get("coverage") == "covered"
                                    and any(e in r.get("cited_ids", []) for e in r["expected"])),
        "answerable_said_not_covered": count(ans, lambda r: r.get("coverage") in ("partial", "not_covered")),
        "coverage_tag_missing": sum(1 for r in called if r.get("coverage") == "missing"),
        "refusals": sum(1 for r in called if r.get("claude") == "refused"),
        "errors": sum(1 for r in called if r.get("claude") == "error"),
        "tokens_in_out": f"{tin} / {tout}",
        "est_cost_usd": round(tin * HAIKU_USD_PER_MTOK[0] / 1e6 + tout * HAIKU_USD_PER_MTOK[1] / 1e6, 4),
    }


def summarize(rows: list[dict]) -> dict:
    ans = [r for r in rows if r["answerable"]]
    una = [r for r in rows if not r["answerable"]]
    count = lambda rs, cond: f"{sum(1 for r in rs if cond(r))}/{len(rs)}"
    return {
        "top5_retrieval_accuracy": count(ans, lambda r: r["hit"]),
        "rank1_accuracy": count(ans, lambda r: r["rank"] == 1),
        "answerable_wrongly_gated": count(ans, lambda r: r["gated"]),
        "answerable_hit_and_not_gated": count(ans, lambda r: r["hit"] and not r["gated"]),
        "unanswerable_gated": count(una, lambda r: r["gated"]),
        "gated_by_reason": {reason: sum(1 for r in rows if r["gate_reason"] == reason)
                            for reason in ("below_threshold", "out_of_scope", "unknown_id")},
        "threshold_in_use": THRESHOLD,
        "marker_margin_in_use": MARKER_MARGIN,
        "threshold_analysis": best_threshold(rows),
    }


def write_report(path: Path, title: str, meta: dict, summary: dict, rows: list[dict]) -> None:
    """Human-readable version of the results: one row per question with its full top 5."""
    top5 = lambda r: ", ".join(f"**{a}** ({s:.2f})" if a in r["expected"] else f"{a} ({s:.2f})"
                               for a, s in r["retrieved"])
    marker = lambda r: f"{r['marker_id']} ({r['marker_score']:.2f}, {', '.join(r['marker_tactics'])})" if r["marker_id"] else "–"
    stopped = lambda r: f"Yes: {r['gate_reason']}" if r["gated"] else "No"
    header = "| ID | Question | {} | Best in-scope | Nearest out-of-scope | Stopped? | Top 5 (score) |"
    lines = [
        f"# {title}", "",
        f"Generated by `scripts/evaluate.py` at {meta['run_at']}. ATT&CK {meta['attack_version']}, "
        f"embedding model `{meta['embedding_model']}`, threshold {THRESHOLD}, marker margin {MARKER_MARGIN}. "
        "Do not edit by hand: re-run the script.", "",
        "| Metric | Result |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in summary.items() if k != "threshold_analysis"], "",
        "Rank = position of the first correct technique in the top 5 (– = not found). Bold = an expected ID. "
        "Scores are cosine similarity; exact-ID lookups show 1.00. Stopped reasons: below_threshold (off-topic), "
        "out_of_scope (an out-of-scope marker beat the best in-scope passage by more than the margin), "
        "unknown_id (names an ATT&CK ID that isn't loaded).", "",
        "## Answerable", "", header.format("Expected / Rank"), "|---|---|---|---|---|---|---|",
        *[f"| {r['id']} | {r['question']} | {' / '.join(r['expected'])} · {r['rank'] or '–'} | {r['top_score']:.2f} | "
          f"{marker(r)} | {stopped(r)} | {top5(r)} |" for r in rows if r["answerable"]], "",
        "## Unanswerable", "", header.format("Kind"), "|---|---|---|---|---|---|---|",
        *[f"| {r['id']} | {r['question']} | {r['kind']} | {r['top_score']:.2f} | {marker(r)} | {stopped(r)} | {top5(r)} |"
          for r in rows if not r["answerable"]], "",
    ]
    called = [r for r in rows if r.get("claude") not in (None, "skipped (gated)")]
    if called:
        cell = lambda s: " ".join((s or "").split()).replace("|", "\\|")
        lines += [
            "## Claude answers", "",
            "Every question that passed the gate, with Claude's own coverage tag (covered / partial / not_covered) "
            "and the ATT&CK IDs its citations point to. Answers shown in full.", "",
            "| ID | Answerable? | Expected | Status | Coverage | Cited IDs | Answer |", "|---|---|---|---|---|---|---|",
            *[f"| {r['id']} | {'yes' if r['answerable'] else 'no'} | {' / '.join(r['expected']) or '–'} | {r['claude']} | "
              f"{r.get('coverage') or '–'} | {', '.join(r.get('cited_ids', [])) or '–'} | {cell(r.get('answer') or r.get('error'))} |"
              for r in called], "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", choices=TEST_SETS, default="main", help="which test set to run")
    parser.add_argument("--claude", action="store_true", help="also call Claude (needs ANTHROPIC_API_KEY, costs money)")
    args = parser.parse_args()

    set_file, prefix = TEST_SETS[args.set]
    test_set = json.loads((EVAL_DIR / set_file).read_text(encoding="utf-8"))
    questions = test_set["questions"]
    retriever = Retriever()
    rows = score_retrieval(questions, retriever)
    summary = summarize(rows)

    if args.claude:
        load_dotenv(ROOT / ".env")
        score_claude(questions, rows, retriever)
        summary.update(summarize_claude(rows))
        prefix = f"{prefix}claude_"  # keep the free retrieval-only results next to the paid run

    meta = {"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "test_set": set_file,
            "attack_version": retriever.index["attack_version"], "embedding_model": retriever.index["model"],
            "top_k": TOP_K}
    results_path, report_path = EVAL_DIR / f"{prefix}results.json", EVAL_DIR / f"{prefix}report.md"
    results_path.write_text(json.dumps({**meta, "summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    write_report(report_path, f"Evaluation report: {set_file}", meta, summary, rows)

    for k, v in summary.items():
        if k != "threshold_analysis":
            print(f"{k:30} {v}")
    t = summary["threshold_analysis"]
    print(f"{'threshold-only suggestion':30} {t['threshold']} ({t['correct']}/{t['of']} vector-routed correct, gap {t['gap']})")
    print("\nMistakes:")
    for r in rows:
        if (r["answerable"] and (not r["hit"] or r["gated"])) or (not r["answerable"] and not r["gated"]):
            m = f"marker {r['marker_id']} {r['marker_score']:.3f}" if r["marker_id"] else ""
            print(f"  {r['id']:5} {r['kind']:13} top={r['top_attack_id']:10} {r['top_score']:.3f} {m:24} "
                  f"expected={r['expected']} stopped={r['gate_reason']}")
    print(f"\nWrote {results_path.relative_to(ROOT)} and {report_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
