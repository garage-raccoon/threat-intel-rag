"""Search page: semantic search over MITRE ATT&CK + CISA KEV, with abstention (Stage 3).

Uses the exact retrieval + abstention logic that was evaluated (scripts/ask.py), so the demo behaves like the numbers
in the README. No API key: live search is free; AI-written answers appear only for pre-generated examples.
"""
import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from ask import DOC_ID, MARKER_MARGIN, THRESHOLD, Retrieval, Retriever, gate_reason  # noqa: E402

EXAMPLES_PATH = ROOT / "data/demo/examples.json"  # owner-approved answers from the live run (build_demo_examples.py)
STUMP_QUERIES = {  # one per abstention reason, so visitors can see the app decline on purpose
    "What's the best pizza in NYC?": "Off-topic: best pizza in NYC",
    "How does ransomware encrypt files to extort victims?": "Out of scope: ransomware encryption",
    "What is T1999.123?": "Made-up ID: T1999.123",
}
SUGGESTED_AFTER_DECLINE = 2
REASONS = {
    "below_threshold": ("Off-topic", "No passage is similar enough to the question (best score {score:.2f} < {t})."),
    "out_of_scope": ("Out of scope", "The closest match is an ATT&CK technique this project deliberately doesn't cover: "
                                     "**{mid} {mname}** ({mtactics}). It beat every covered source by more than {m}."),
    "unknown_id": ("Unknown ID", "{ids}"),
}
ID_FORMATS = "ATT&CK IDs look like T1234 or T1234.567; CVE IDs look like CVE-2024-1234"


def unknown_id_detail(ids: list[str]) -> str:
    """A badly formatted ID and a well-formed ID that doesn't exist get different explanations (D56)."""
    invalid = [i for i in ids if not DOC_ID.fullmatch(i)]
    missing = [i for i in ids if DOC_ID.fullmatch(i)]
    parts = []
    if invalid:
        parts.append(f"**{', '.join(invalid)}** {'is not a valid ID' if len(invalid) == 1 else 'are not valid IDs'} "
                     f"({ID_FORMATS}).")
    if missing:
        parts.append(f"**{', '.join(missing)}** {'has' if len(missing) == 1 else 'have'} the right format but "
                     f"{'is' if len(missing) == 1 else 'are'} not in the knowledge base. Similar-looking IDs are never "
                     "substituted.")
    return " ".join(parts)

@st.cache_resource(show_spinner="Loading the search index and embedding model…")
def load_retriever() -> Retriever:
    return Retriever()


@st.cache_data
def load_examples() -> dict[str, dict]:
    """Question -> example, in the approved display order."""
    if not EXAMPLES_PATH.exists():
        return {}
    return {e["question"]: e for e in json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))["examples"]}


def passage_card(p: dict) -> None:
    header, _, body = p["text"].partition("\n")
    # KEV names are "<vendor> <product>: <vulnerability name>" and the vulnerability name already starts with the
    # vendor and product, so show only the part after the colon (display only; the indexed text is unchanged).
    name = p["name"].split(": ", 1)[-1] if p["source"] == "kev" else p["name"]
    label = f"**{p['doc_id']}** {name}  ·  {p['section']}  ·  " + ("exact ID match" if p["match"] == "exact" else f"score {p['score']:.2f}")
    with st.expander(label):
        st.markdown(body.replace("\n", "  \n"))
        st.markdown(f"[Source]({p['url']})")


def set_question(q: str) -> None:
    st.session_state.q = q


def pick(key: str) -> None:
    """Pill callback: copy the picked question into the search box, then clear the pill so it doesn't stay lit."""
    if st.session_state[key]:
        set_question(st.session_state[key])
    st.session_state[key] = None


def show_abstention(r: Retrieval, reason: str, suggestions: dict[str, str]) -> None:
    title, detail = REASONS[reason]
    if reason == "unknown_id":
        title = "Invalid ID" if not any(DOC_ID.fullmatch(i) for i in r.unknown_ids) else title
    m = r.marker or {}
    st.warning(f"**I don't have information on that.** ({title})")
    st.caption(detail.format(score=r.top_score, t=THRESHOLD, m=MARKER_MARGIN, ids=unknown_id_detail(r.unknown_ids),
                             mid=m.get("attack_id", ""), mname=m.get("name", ""), mtactics=", ".join(m.get("tactics", []))))
    if suggestions:
        st.markdown("Try a covered question instead:")
        for q, label in suggestions.items():
            st.button(label, on_click=set_question, args=(q,), key=f"suggest-{q}")


def show_example_answer(example: dict) -> None:
    st.markdown("#### Answer")
    st.info(f"Pre-generated with `{example['model']}` on {example['generated']} through the same pipeline "
            "(not generated live: this demo uses no API key).")
    st.markdown(example["answer"])
    if example.get("citations"):
        st.markdown("**Sources:** " + " · ".join(f"[{i}] [{c['doc_id']}]({c['url']})"
                                                 for i, c in enumerate(example["citations"], 1)))


retriever = load_retriever()
examples = load_examples()
labels = {q: e["label"] for q, e in examples.items()} | STUMP_QUERIES

st.title("Threat Intel RAG")
st.markdown("Ask about an attack technique or a known exploited vulnerability. Answers come only from **MITRE ATT&CK** "
            "and the **CISA Known Exploited Vulnerabilities** catalog, and the app says *I don't know* when a question "
            "is off-topic or outside that scope.")

with st.container(border=True):
    covered, kinds = st.columns(2)
    covered.markdown("**What's covered**\n- ATT&CK **Initial Access** and **Credential Access** techniques\n"
                     "- Every **CISA KEV** entry (vulnerabilities attackers are known to exploit)\n"
                     "- Not covered: other ATT&CK tactics (e.g. ransomware impact), compliance, general IT")
    kinds.markdown("**Ways to ask**\n- Describe an incident: *\"Users are flooded with MFA push prompts\"*\n"
                   "- Look up an ID: *T1110.003* or *CVE-2024-3400*\n"
                   "- Ask how to detect or stop something: *\"How do I detect password spraying?\"*")

st.pills("★ Examples with a pre-generated AI answer", list(examples), format_func=labels.get, key="pick_example",
         on_change=pick, args=("pick_example",))
st.pills("Try to stump it", list(STUMP_QUERIES), format_func=labels.get, key="pick_stump",
         on_change=pick, args=("pick_stump",))

question = st.text_input("Your question", key="q", placeholder="e.g. How do I detect password spraying?")
st.caption("Live search runs on every question. AI-written answers are pre-generated for the ★ examples, so this "
           "public demo holds no API key (a deliberate security choice).")

idx = retriever.index
st.sidebar.caption(f"Index: ATT&CK {idx['attack_version']} · {idx.get('kev_entries', 0):,} KEV entries · "
                   f"{len(idx['passages']):,} passages · `{idx['model']}`")
if not question.strip():
    st.stop()

r = retriever.retrieve(question)
reason = gate_reason(r)
if reason:
    covered = [q for q in examples if examples[q]["coverage"] == "covered"][:SUGGESTED_AFTER_DECLINE]
    show_abstention(r, reason, {q: labels[q] for q in covered})
    st.stop()

if question in examples:
    show_example_answer(examples[question])
else:
    st.caption("Showing the sources an answer would be built from. AI-written answers are available for the ★ examples.")

kev = retriever.kev_to_send(r)
left, right = st.columns(2)
with left:
    st.subheader("ATT&CK techniques")
    for p in r.passages:
        passage_card(p)
    if not r.passages:
        st.caption("None matched.")
with right:
    st.subheader("Known exploited vulnerabilities")
    for p in kev:
        passage_card(p)
    if not kev:
        st.caption("No KEV entry is close enough to show.")
if r.marker:
    st.caption(f"Nearest out-of-scope technique: {r.marker['attack_id']} {r.marker['name']} ({r.marker['score']:.2f}); "
               "used only to detect questions this project doesn't cover.")
