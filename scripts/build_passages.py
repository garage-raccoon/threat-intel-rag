"""Turn ATT&CK techniques and CISA KEV entries into retrieval passages.

Usage: .venv/bin/python -I scripts/build_passages.py
Reads  data/processed/techniques.json (parse_stix.py) and data/history/kev_state.csv (fetch_kev.py)
Writes data/processed/passages.json
Every passage and marker gets a content fingerprint (passage_hash) so embed_passages.py re-embeds only
what changed. Each ATT&CK section is its own passage, split if it exceeds the model's 512-token limit.
"""
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

from sentence_transformers import SentenceTransformer

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_PATH = ROOT / "data/processed/techniques.json"
KEV_STATE_PATH = ROOT / "data/history/kev_state.csv"
OUT_PATH = ROOT / "data/processed/passages.json"
MODEL_NAME = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"  # keep in sync with embed_passages.py
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"

SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


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


def passage(doc_id: str, source: str, name: str, tactics: list[str], section: str, text: str, url: str,
            packer: Packer, suffix: str = "") -> dict:
    return {"passage_id": f"{doc_id}#{section}{suffix}", "doc_id": doc_id, "source": source,
            "attack_id": doc_id if source == "attack" else None, "name": name, "tactics": tactics,
            "section": section, "text": text, "n_tokens": packer.count(text), "url": url,
            "passage_hash": fingerprint(text)}


def build_attack(techniques: list[dict], packer: Packer) -> list[dict]:
    passages = []
    for tech in techniques:
        for section, lines in section_lines(tech).items():
            if not lines:
                continue
            header = f"{tech['attack_id']} {tech['name']} ({', '.join(tech['tactics'])}): {section.capitalize()}"
            texts = packer.pack(header, lines)
            for i, text in enumerate(texts, 1):
                passages.append(passage(tech["attack_id"], "attack", tech["name"], tech["tactics"], section, text,
                                        tech["url"], packer, f"-{i}" if len(texts) > 1 else ""))
    return passages


def build_kev(rows: list[dict], packer: Packer) -> list[dict]:
    """One passage per KEV entry (split only if it ever exceeds the token limit)."""
    passages = []
    for r in rows:
        name = f"{r['vendorProject']} {r['product']}: {r['vulnerabilityName']}"
        header = f"{r['cveID']} {name} (Known Exploited Vulnerability, added to CISA KEV {r['dateAdded']})"
        lines = [r["shortDescription"],
                 f"Required action: {r['requiredAction']} (due {r['dueDate']})",
                 f"Known ransomware campaign use: {r['knownRansomwareCampaignUse']}"]
        if r["cwes"]:
            lines.append(f"Weaknesses: {r['cwes'].replace(';', ', ')}")
        texts = packer.pack(header, [l for l in lines if l.strip()])
        for i, text in enumerate(texts, 1):
            passages.append(passage(r["cveID"], "kev", name, [], "vulnerability", text, NVD_URL.format(r["cveID"]),
                                    packer, f"-{i}" if len(texts) > 1 else ""))
    return passages


def main() -> None:
    source = json.loads(TECHNIQUES_PATH.read_text(encoding="utf-8"))
    kev_rows = []
    if KEV_STATE_PATH.exists():
        with KEV_STATE_PATH.open(newline="", encoding="utf-8") as f:
            kev_rows = list(csv.DictReader(f))

    model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION)
    packer = Packer(model.tokenizer, model.max_seq_length)
    passages = build_attack(source["techniques"], packer) + build_kev(kev_rows, packer)

    over = [p["passage_id"] for p in passages if p["n_tokens"] > packer.max_tokens]
    if over:
        sys.exit(f"Passages still over {packer.max_tokens} tokens: {over}")

    # One description-only passage per out-of-scope technique. Never sent to Claude; the model truncates
    # anything past its limit, which is fine for a marker that only needs the gist.
    markers = []
    for m in source["out_of_scope_markers"]:
        text = f"{m['attack_id']} {m['name']} ({', '.join(m['tactics'])}): Description\n{m['description']}"
        markers.append({"attack_id": m["attack_id"], "name": m["name"], "tactics": m["tactics"], "text": text,
                        "passage_hash": fingerprint(text)})

    OUT_PATH.write_text(json.dumps({
        "attack_version": source["attack_version"],
        "kev_entries": len(kev_rows),
        "model": MODEL_NAME,
        "max_tokens": packer.max_tokens,
        "passages": passages,
        "markers": markers,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    by_source = {s: [p for p in passages if p["source"] == s] for s in ("attack", "kev")}
    split = sorted({p["passage_id"].split("-")[0] for p in passages if re.search(r"-\d+$", p["passage_id"])})
    print(f"{len(source['techniques'])} techniques -> {len(by_source['attack'])} passages; "
          f"{len(kev_rows)} KEV entries -> {len(by_source['kev'])} passages "
          f"(max {max(p['n_tokens'] for p in passages)} / {packer.max_tokens} tokens) -> {OUT_PATH.relative_to(ROOT)}")
    print(f"Split into several passages ({len(split)}): {', '.join(split) or 'none'}")
    print(f"Out-of-scope markers: {len(markers)}")


if __name__ == "__main__":
    main()
