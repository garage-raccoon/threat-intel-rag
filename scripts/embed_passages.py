"""Stage 1, step 4: embed every passage and save vectors + metadata.

Usage: .venv/bin/python -I scripts/embed_passages.py
Writes data/processed/vectors.npy (row N = passage N) and data/processed/index.json.
See research.md D14.
"""
import json
import sys
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

# --- CONFIG ---
ROOT = Path(__file__).resolve().parent.parent
PASSAGES_PATH = ROOT / "data/processed/passages.json"
VECTORS_PATH = ROOT / "data/processed/vectors.npy"
MARKER_VECTORS_PATH = ROOT / "data/processed/marker_vectors.npy"
INDEX_PATH = ROOT / "data/processed/index.json"
MODEL_NAME = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
# From the model card: add to queries only; "no instruction needs to be added to passages".
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


def main() -> None:
    source = json.loads(PASSAGES_PATH.read_text(encoding="utf-8"))
    if source["model"] != MODEL_NAME:
        sys.exit(f"passages.json was sized for {source['model']}, not {MODEL_NAME}: re-run build_passages.py")
    passages = source["passages"]

    markers = source["markers"]
    model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION)
    encode = lambda texts: model.encode(
        texts,
        normalize_embeddings=True,  # unit length, so cosine similarity == dot product in step 5
        batch_size=32,
        show_progress_bar=True,
        convert_to_numpy=True,
    ).astype(np.float32)
    vectors = encode([p["text"] for p in passages])
    marker_vectors = encode([m["text"] for m in markers])

    np.save(VECTORS_PATH, vectors)
    np.save(MARKER_VECTORS_PATH, marker_vectors)
    INDEX_PATH.write_text(json.dumps({
        "attack_version": source["attack_version"],
        "model": MODEL_NAME,
        "model_revision": MODEL_REVISION,
        "dimensions": int(vectors.shape[1]),
        "normalized": True,
        "query_instruction": QUERY_INSTRUCTION,
        "count": len(passages),
        "passages": passages,  # same order as the rows of vectors.npy
        # same order as the rows of marker_vectors.npy; text omitted (markers are never shown or sent to Claude)
        "markers": [{k: m[k] for k in ("attack_id", "name", "tactics")} for m in markers],
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Embedded {vectors.shape[0]} passages + {marker_vectors.shape[0]} markers x {vectors.shape[1]} dims "
          f"-> {VECTORS_PATH.name}, {MARKER_VECTORS_PATH.name}, {INDEX_PATH.name}")


if __name__ == "__main__":
    main()
