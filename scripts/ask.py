"""Stage 1, step 5: answer a question from the top-5 ATT&CK passages, with citations.

Usage: .venv/bin/python -I scripts/ask.py "How do attackers use spearphishing links?"
Needs ANTHROPIC_API_KEY in .env, except when the question is gated out (no API call is made).
See research.md D16-D18.
"""
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import anthropic
import numpy as np
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
VECTORS_PATH = ROOT / "data/processed/vectors.npy"
MARKER_VECTORS_PATH = ROOT / "data/processed/marker_vectors.npy"
INDEX_PATH = ROOT / "data/processed/index.json"
TOP_K = 5
THRESHOLD = 0.555  # Set from step 6 scores (D29): mid-gap between 0.512 (off-topic) and 0.599 (lowest answerable)
# Out-of-scope marker must beat the best in-scope passage by more than this to answer NO_INFO (D32, D33).
MARKER_MARGIN = 0.02
CLAUDE_MODEL = "claude-haiku-5-5"
NO_INFO = "I don't have information on that."
# Embeddings can't tell IDs apart ("T1110.003" retrieves the wrong technique), so IDs are matched exactly (D25).
ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
SYSTEM_PROMPT = (
    "You answer security analysts' questions about MITRE ATT&CK techniques.\n"
    "- Answer only from the provided passages. Do not add facts from outside them.\n"
    "- Name the ATT&CK ID (e.g. T1566.002) of each technique you discuss.\n"
    "- Where relevant, cover what the attack is, how to detect it, and how to mitigate it.\n"
    "- If the passages do not answer the question, say so plainly in your first sentence. "
    "You may then offer the closest related guidance from the passages, clearly labeled as related "
    "rather than as the answer. Never guess.\n"
    "- Begin your reply with exactly one line, before anything else:\n"
    "  COVERAGE: covered       (the passages answer the question)\n"
    "  COVERAGE: partial       (they don't answer it, but you offer related guidance from them)\n"
    "  COVERAGE: not_covered   (they don't answer it and nothing related is useful)"
)
# Citations can't be combined with structured outputs (output_config.format returns a 400), so the coverage
# judgment comes as a tagged first line that is parsed and removed from the shown answer (research.md D39).
COVERAGE_LINE = re.compile(r"^\s*COVERAGE:\s*(covered|partial|not_covered)\b[^\n]*\n?", re.IGNORECASE)


def split_coverage(text: str) -> tuple[str, str]:
    """('covered' | 'partial' | 'not_covered' | 'missing', text without the tag line)."""
    m = COVERAGE_LINE.match(text)
    return (m.group(1).lower(), text[m.end():]) if m else ("missing", text)


@dataclass
class Retrieval:
    passages: list[dict]
    unknown_ids: list[str] = field(default_factory=list)  # ATT&CK IDs named in the question but not loaded
    marker: dict | None = None  # nearest out-of-scope technique: {attack_id, name, tactics, score}


class Retriever:
    def __init__(self) -> None:
        self.index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        self.vectors = np.load(VECTORS_PATH)
        self.marker_vectors = np.load(MARKER_VECTORS_PATH)
        if (len(self.index["passages"]), len(self.index["markers"])) != (len(self.vectors), len(self.marker_vectors)):
            sys.exit("index.json and the .npy vector files are out of sync: re-run embed_passages.py")
        self.model = SentenceTransformer(self.index["model"], revision=self.index["model_revision"])
        self.by_attack_id: dict[str, list[int]] = {}
        for row, p in enumerate(self.index["passages"]):
            self.by_attack_id.setdefault(p["attack_id"], []).append(row)

    def search(self, question: str, k: int = TOP_K) -> tuple[list[dict], dict]:
        """Top-k in-scope passages, plus the single nearest out-of-scope marker."""
        query = self.model.encode(self.index["query_instruction"] + question, normalize_embeddings=True)
        scores = self.vectors @ query
        marker_scores = self.marker_vectors @ query
        j = int(marker_scores.argmax())
        return ([{**self.index["passages"][i], "score": float(scores[i]), "match": "vector"}
                 for i in np.argsort(-scores)[:k]],
                {**self.index["markers"][j], "score": float(marker_scores[j])})

    def exact(self, question: str) -> tuple[list[dict], list[str]]:
        """Passages for ATT&CK IDs named in the question, plus any named IDs that aren't in the index."""
        ids = list(dict.fromkeys(m.upper() for m in ATTACK_ID.findall(question)))
        rows = [r for i in ids for r in self.by_attack_id.get(i, [])]
        return ([{**self.index["passages"][r], "score": 1.0, "match": "exact"} for r in rows],
                [i for i in ids if i not in self.by_attack_id])

    def retrieve(self, question: str, k: int = TOP_K) -> Retrieval:
        """Passages of every known ATT&CK ID named in the question; vector search only when none is named.

        No vector top-up on an exact hit: for an ID-only question the vector results are near-random.
        """
        exact, unknown_ids = self.exact(question)
        if exact:
            return Retrieval(exact, unknown_ids)
        passages, marker = self.search(question, k)
        return Retrieval(passages, unknown_ids, marker)


def ask_claude(client: anthropic.Anthropic, question: str, passages: list[dict], unknown_ids: list[str]) -> dict:
    documents = [{
        "type": "document",
        "source": {"type": "text", "media_type": "text/plain", "data": p["text"]},
        "title": f"{p['passage_id']}: {p['name']}",
        "citations": {"enabled": True},
    } for p in passages]

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=16000,
        output_config={"effort": "medium"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": [*documents, {"type": "text", "text": question + (
            f"\n\n(Not in the knowledge base: {', '.join(unknown_ids)}.)" if unknown_ids else "")}]}],
    )

    # Haiku 5.5 has no server-side refusal fallback (D17): check before reading content.
    if response.stop_reason == "refusal":
        details = response.stop_details
        return {"status": "refused", "refusal_category": details.category if details else None,
                "answer": None, "citations": [], "usage": response.usage.to_dict()}

    answer, citations, coverage = [], [], None
    for block in response.content:
        if block.type != "text":
            continue
        text = block.text
        if coverage is None:  # the tag is in the first text block
            coverage, text = split_coverage(text)
        answer.append(text)
        for c in block.citations or []:
            source = passages[c.document_index]
            if source["passage_id"] not in [x["passage_id"] for x in citations]:
                citations.append({"passage_id": source["passage_id"], "attack_id": source["attack_id"],
                                  "url": source["url"], "cited_text": c.cited_text})
            answer.append(f" [{[x['passage_id'] for x in citations].index(source['passage_id']) + 1}]")

    return {"status": "answered" if response.stop_reason == "end_turn" else response.stop_reason,
            "coverage": coverage or "missing",
            "answer": "".join(answer).strip(), "citations": citations, "usage": response.usage.to_dict()}


def gate_reason(r: Retrieval, threshold: float = THRESHOLD, margin: float = MARKER_MARGIN) -> str | None:
    """Why we answer NO_INFO without calling Claude, or None to go ahead."""
    if r.passages[0]["match"] == "exact":
        return None
    if r.unknown_ids:  # an ID we don't hold must not fall back to similar-looking IDs (D25)
        return "unknown_id"
    if r.passages[0]["score"] < threshold:  # off-topic (D29)
        return "below_threshold"
    if r.marker and r.marker["score"] - r.passages[0]["score"] > margin:  # covered by a topic we didn't load (D33)
        return "out_of_scope"
    return None


def answer(question: str, retriever: Retriever, client: anthropic.Anthropic | None = None) -> dict:
    """Full step 5 for one question. Step 6 imports this to run the test set."""
    r = retriever.retrieve(question)
    result = {"question": question, "top_score": r.passages[0]["score"], "threshold": THRESHOLD,
              "unknown_ids": r.unknown_ids, "nearest_out_of_scope": r.marker,
              "retrieved": [{"passage_id": p["passage_id"], "attack_id": p["attack_id"], "score": p["score"],
                             "match": p["match"]} for p in r.passages]}
    if reason := gate_reason(r):
        return {**result, "status": "gated", "gate_reason": reason, "answer": NO_INFO, "citations": []}
    return {**result, **ask_claude(client or anthropic.Anthropic(), question, r.passages, r.unknown_ids)}


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit('Usage: ask.py "your question"')
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    question = " ".join(sys.argv[1:])

    try:
        result = answer(question, Retriever())
    except anthropic.AuthenticationError:
        sys.exit("Claude API rejected the credentials: set ANTHROPIC_API_KEY in .env")
    except anthropic.RateLimitError:
        sys.exit("Rate limited by the Claude API (after the SDK's automatic retries): try again shortly")
    except anthropic.APIStatusError as e:
        sys.exit(f"Claude API error {e.status_code}: {e.message} (request id {e.request_id})")
    except anthropic.APIConnectionError:
        sys.exit("Could not reach the Claude API: check your network connection")

    print("Retrieved:")
    for r in result["retrieved"]:
        print(f"  {r['score']:.3f}  {r['match']:6}  {r['passage_id']}")
    if result["unknown_ids"]:
        print(f"  not in index: {', '.join(result['unknown_ids'])}")
    if m := result["nearest_out_of_scope"]:
        print(f"  nearest out-of-scope: {m['score']:.3f}  {m['attack_id']} {m['name']} ({', '.join(m['tactics'])})")
    print(f"\n[{result['status']}{': ' + result['gate_reason'] if result.get('gate_reason') else ''}"
          f"{' | coverage: ' + result['coverage'] if result.get('coverage') else ''}] "
          f"top score {result['top_score']:.3f} (threshold {THRESHOLD}, marker margin {MARKER_MARGIN})\n")

    if result["status"] == "refused":
        print(f"Claude declined to answer (category: {result['refusal_category']}).")
        return
    print(result["answer"])
    if result["citations"]:
        print("\nSources:")
        for n, c in enumerate(result["citations"], 1):
            print(f"  [{n}] {c['passage_id']}  {c['url']}")
    if "usage" in result:
        u = result["usage"]
        print(f"\nTokens: {u['input_tokens']} in / {u['output_tokens']} out")


if __name__ == "__main__":
    main()
