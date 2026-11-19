"""Embed passages and markers, reusing cached vectors for text that hasn't changed.

Usage: .venv/bin/python -I scripts/embed_passages.py [--no-cache]
Writes data/processed/vectors.npy (row N = passage N), marker_vectors.npy and index.json.
Cache: data/processed/embedding_cache.npz, keyed by passage_hash and tied to the exact model + revision, so a
changed passage gets a new hash and is re-embedded, and a model change invalidates everything.
Not committed: a fresh checkout simply re-embeds all. Plain .npy files, no vector database: ~2.7k vectors fit in memory.
"""
import argparse
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
CACHE_PATH = ROOT / "data/processed/embedding_cache.npz"
MODEL_NAME = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
# From the model card: add to queries only; "no instruction needs to be added to passages".
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


def load_cache(use_cache: bool) -> dict[str, np.ndarray]:
    if not use_cache or not CACHE_PATH.exists():
        return {}
    data = np.load(CACHE_PATH)
    if str(data["model"]) != f"{MODEL_NAME}@{MODEL_REVISION}":
        return {}  # vectors from another model are meaningless here
    return dict(zip(data["hashes"].tolist(), data["vectors"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-cache", action="store_true", help="re-embed everything")
    args = parser.parse_args()

    source = json.loads(PASSAGES_PATH.read_text(encoding="utf-8"))
    if source["model"] != MODEL_NAME:
        sys.exit(f"passages.json was sized for {source['model']}, not {MODEL_NAME}: re-run build_passages.py")
    passages, markers = source["passages"], source["markers"]

    cache = load_cache(not args.no_cache)
    items = {p["passage_hash"]: p["text"] for p in passages + markers}
    todo = [h for h in items if h not in cache]
    if todo:
        model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION)
        fresh = model.encode([items[h] for h in todo], normalize_embeddings=True,  # unit length: cosine == dot product
                             batch_size=32, show_progress_bar=True, convert_to_numpy=True).astype(np.float32)
        cache.update(zip(todo, fresh))

    vectors = np.stack([cache[p["passage_hash"]] for p in passages])
    marker_vectors = np.stack([cache[m["passage_hash"]] for m in markers])
    np.save(VECTORS_PATH, vectors)
    np.save(MARKER_VECTORS_PATH, marker_vectors)
    keep = sorted(items)  # drop vectors for text that no longer exists
    np.savez(CACHE_PATH, model=np.array(f"{MODEL_NAME}@{MODEL_REVISION}"), hashes=np.array(keep),
             vectors=np.stack([cache[h] for h in keep]))

    INDEX_PATH.write_text(json.dumps({
        "attack_version": source["attack_version"],
        "kev_entries": source.get("kev_entries", 0),
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

    print(f"{len(passages)} passages + {len(markers)} markers: embedded {len(todo)} new/changed, "
          f"reused {len(items) - len(todo)} from cache -> {VECTORS_PATH.name}, {MARKER_VECTORS_PATH.name}, {INDEX_PATH.name}")


if __name__ == "__main__":
    main()
