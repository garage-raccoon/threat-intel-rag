"""Stage 1, step 3: turn each technique into retrieval passages that fit the embedding model.

Usage: .venv/bin/python -I scripts/build_passages.py [techniques_path] [out_path]
See research.md D9 / D12 for the passage format.
"""
import json
import re
import sys
from pathlib import Path

from sentence_transformers import SentenceTransformer

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_PATH = ROOT / "data/processed/techniques.json"
OUT_PATH = ROOT / "data/processed/passages.json"
MODEL_NAME = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"  # keep in sync with embed_passages.py

SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def section_lines(tech: dict) -> dict[str, list[str]]:
    one_line = lambda s: " ".join(s.split())
    return {
        "description": tech["description"].splitlines(),
        "detection": [
            f"- {d['name']} [{', '.join(a['platforms'])}]: {one_line(a['text'])}"
            for d in tech["detection_strategies"] for a in d["analytics"]
        ],
        "mitigations": [f"- {m['id']} {m['name']}: {one_line(m['text'])}" for m in tech["mitigations"]],
    }


class Packer:
    def __init__(self, tokenizer, max_tokens: int):
        self.tokenizer, self.max_tokens = tokenizer, max_tokens

    def count(self, text: str) -> int:
        return len(self.tokenizer(text)["input_ids"])  # includes [CLS]/[SEP], as the model sees it

    def pack(self, header: str, lines: list[str]) -> list[str]:
        """Greedily fill passages line by line; a line too long alone is split into sentences."""
        units = []
        for line in lines:
            units += SENTENCE_END.split(line) if self.count(f"{header}\n{line}") > self.max_tokens else [line]

        passages, current = [], []
        for unit in units:
            if current and self.count("\n".join([header, *current, unit])) > self.max_tokens:
                passages.append("\n".join([header, *current]))
                current = []
            current.append(unit)
        if current:
            passages.append("\n".join([header, *current]))
        return passages


def build(techniques: list[dict], packer: Packer) -> list[dict]:
    passages = []
    for tech in techniques:
        for section, lines in section_lines(tech).items():
            if not lines:
                continue
            header = f"{tech['attack_id']} {tech['name']} ({', '.join(tech['tactics'])}): {section.capitalize()}"
            texts = packer.pack(header, lines)
            for i, text in enumerate(texts, 1):
                suffix = f"-{i}" if len(texts) > 1 else ""
                passages.append({
                    "passage_id": f"{tech['attack_id']}#{section}{suffix}",
                    "attack_id": tech["attack_id"],
                    "name": tech["name"],
                    "tactics": tech["tactics"],
                    "section": section,
                    "text": text,
                    "n_tokens": packer.count(text),
                    "url": tech["url"],
                })
    return passages


def main() -> None:
    techniques_path = Path(sys.argv[1]) if len(sys.argv) > 1 else TECHNIQUES_PATH
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else OUT_PATH
    source = json.loads(techniques_path.read_text(encoding="utf-8"))

    model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION)
    packer = Packer(model.tokenizer, model.max_seq_length)
    passages = build(source["techniques"], packer)

    over = [p["passage_id"] for p in passages if p["n_tokens"] > packer.max_tokens]
    if over:
        sys.exit(f"Passages still over {packer.max_tokens} tokens: {over}")

    # One description-only passage per out-of-scope technique. Never sent to Claude; the model truncates
    # anything past its limit, which is fine for a marker that only needs the gist (research.md D33).
    markers = [{
        "attack_id": m["attack_id"], "name": m["name"], "tactics": m["tactics"],
        "text": f"{m['attack_id']} {m['name']} ({', '.join(m['tactics'])}): Description\n{m['description']}",
    } for m in source["out_of_scope_markers"]]

    out_path.write_text(json.dumps({
        "attack_version": source["attack_version"],
        "model": MODEL_NAME,
        "max_tokens": packer.max_tokens,
        "passages": passages,
        "markers": markers,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    split = sorted({p["passage_id"].split("-")[0] for p in passages if re.search(r"-\d+$", p["passage_id"])})
    print(f"{len(source['techniques'])} techniques -> {len(passages)} passages "
          f"(max {max(p['n_tokens'] for p in passages)} / {packer.max_tokens} tokens) -> {out_path}")
    print(f"Sections split further ({len(split)}): {', '.join(split) or 'none'}")
    print(f"Out-of-scope markers: {len(markers)}")


if __name__ == "__main__":
    main()
