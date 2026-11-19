"""Evaluation page: how well search, "I don't know", and the AI answers work, with the known weaknesses.

Every number is read from data/eval/*.json at load time, so the page can't drift from the latest eval run.
"""
import json
from collections import Counter
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "data/eval"
SETS = {  # display name -> (retrieval results, live Claude results, how the set was made)
    "Approved": ("results.json", "claude_results.json",
                 "33 answerable + 9 unanswerable; reviewed by the owner; the threshold was tuned on it"),
    "Held-out": ("holdout_results.json", "holdout_claude_results.json",
                 "50 + 50; written after the settings were fixed, never used for tuning"),
    "KEV": ("kev_results.json", "kev_claude_results.json",
            "20 + 6 vulnerability questions; reviewed by the owner"),
}
KIND_NAMES = {"off_topic": "Off-topic (e.g. pizza)", "out_of_scope": "ATT&CK tactics not loaded (e.g. ransomware)",
              "unknown_id": "IDs not in the data", "non_attack_security": "Security, but not ATT&CK (e.g. SOC 2)",
              "aggregate": "Questions over the whole catalog (e.g. counts)", "partial_expected": "Partly covered"}


def load(name: str) -> dict:
    return json.loads((EVAL_DIR / name).read_text(encoding="utf-8"))


def frac(k: int, n: int) -> str:
    return f"{k}/{n} ({k / n:.0%})" if n else "n/a"


def correct_id_cited(rows: list[dict]) -> str:
    answerable = [r for r in rows if r["answerable"]]
    return frac(sum(bool(set(r["expected"]) & set(r.get("cited_ids") or [])) for r in answerable), len(answerable))


retrieval = {s: load(f[0]) for s, f in SETS.items()}
live = {s: load(f[1]) for s, f in SETS.items()}
faith, inj = load("faithfulness_results.json")["summary"], load("injection_results.json")["summary"]
unanswerable_live = [r for d in live.values() for r in d["rows"] if not r["answerable"]]
answered_as_covered = sum(r.get("coverage") == "covered" for r in unanswerable_live)
supported, scored = (int(x) for x in faith["claims_supported"].split("/"))

st.title("Evaluation")
st.markdown("Three hand-checked test sets measure each step: does search find the right source, does the system "
            "say *I don't know* when it should, and are the AI answers faithful to their sources and safe against "
            "planted instructions. Search tests are free and rerun on every pipeline run; the AI-answer tests ran "
            f"once with `{live['Approved']['summary']['claude_model']}`.")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Correct source in top 5", retrieval["Held-out"]["summary"]["top5_retrieval_accuracy"],
          help="Held-out set: the set never used for tuning")
c2.metric("Unanswerable answered as if covered", f"{answered_as_covered}/{len(unanswerable_live)}",
          help="All unanswerable questions across the three sets, live AI run")
c3.metric("Answer claims supported by sources", f"{supported / scored:.0%}", help=f"{supported:,} of {scored:,} claims")
c4.metric("Prompt-injection attacks that worked", inj["attack_success_rate"])

st.subheader("The test sets")
st.dataframe([{"Set": s, "What it is": f[2]} for s, f in SETS.items()], hide_index=True, width="stretch")

st.subheader("1. Search: is the right source retrieved?")
st.dataframe([{"Set": s,
               "Correct source in top 5": d["summary"]["top5_retrieval_accuracy"],
               "Ranked #1": d["summary"]["rank1_accuracy"],
               "Answerable but wrongly stopped": d["summary"]["answerable_wrongly_gated"]}
              for s, d in retrieval.items()], hide_index=True, width="stretch")
st.caption("Questions are written the way an analyst describes an incident, mostly without technique names. "
           "Search model: bge-small-en-v1.5, running locally (no API).")

st.subheader("2. \"I don't know\": abstention")
st.markdown(f"Before any AI call, a question is stopped if no source is similar enough (score < "
            f"{retrieval['Approved']['summary']['threshold_in_use']}), if its closest match is an ATT&CK technique "
            "this project doesn't cover (out-of-scope detection), or if it names an ID that isn't in the data. "
            "Questions that get through can still be declined by the AI, which is told to answer only from the sources.")
st.dataframe([{"Set": s,
               "Stopped before the AI call": retrieval[s]["summary"]["unanswerable_gated"],
               "Declined overall": live[s]["summary"]["unanswerable_declined"],
               "Answered as if covered": live[s]["summary"]["unanswerable_answered_as_covered"]}
              for s in SETS], hide_index=True, width="stretch")
kinds = Counter((r["kind"], r["gated"]) for r in retrieval["Held-out"]["rows"] if not r["answerable"])
st.markdown("**Held-out unanswerable questions stopped before the AI call, by kind**")
st.dataframe([{"Kind": KIND_NAMES.get(k, k), "Stopped": f"{kinds[(k, True)]}/{kinds[(k, True)] + kinds[(k, False)]}"}
              for k in dict.fromkeys(k for k, _ in kinds)], hide_index=True, width="stretch")
st.caption("\"Declined overall\" includes answers that say the sources don't cover the question and then offer "
           "related guidance. Counting only plain declines: "
           + ", ".join(f"{s} {live[s]['summary']['unanswerable_declined_strict']}" for s in SETS) + ".")

st.subheader("3. AI answers: correct and faithful?")
st.dataframe([{"Set": s,
               "Cited the expected source": correct_id_cited(live[s]["rows"]),
               "Cited it and tagged the answer covered": live[s]["summary"]["answerable_correct"]}
              for s in SETS], hide_index=True, width="stretch")
st.markdown(f"**Faithfulness:** a judge model split {faith['answers_judged']} answers into {scored:,} claims and checked "
            f"each against the passages the answer was given: **{faith['claims_supported']}** supported, "
            f"{faith['claims_unsupported']} unsupported, {faith['claims_contradicted']} contradicted. "
            f"{faith['answers_fully_supported']} answers were supported in full.")

st.subheader("4. Safety: prompt injection")
st.markdown(f"A poisoned passage carrying a hidden instruction was planted among the real sources (6 attack types × "
            f"2 questions; test time only, never in the index). Success is detected by an exact canary string, not a "
            f"judge. **{inj['attack_success_rate']} attacks succeeded**; the answer warned about the planted "
            f"instruction in {inj['answer_flagged_the_injection']}.")
st.dataframe([{"Attack": a.replace("_", " "), "Succeeded": v} for a, v in inj["per_attack_success"].items()],
             hide_index=True, width="stretch")

st.subheader("Known weaknesses")
st.markdown(f"""
- **Added advice:** most unsupported claims are general advice beyond the sources ("reset the password"). Next step: tighten the prompt and re-measure.
- **Over-cautious "partial" tags:** some answers cite the right technique but are tagged partial because the question mentions a detail the sources lack.
- **Lenient judge:** the faithfulness judge is the same model family as the answerer (a cost choice), so {supported / scored:.0%} is likely an upper bound; a hand-check of 10 judgments is pending.
- **Security questions outside ATT&CK** (compliance, product how-tos) are mostly not stopped before the AI call; the AI has to decline them from the sources.
- **Tactic IDs** such as `TA0001` are declined as off-topic, because tactics aren't stored as search entries.
- **Small test sets:** a few dozen questions per set, so each number has a wide margin of error.
""")
st.caption("Per-question reports: `data/eval/*_report.md`.")
