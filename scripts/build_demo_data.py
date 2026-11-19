"""Hosting: rebuild the generated data the demo needs on a fresh server.

Usage: .venv/bin/python -I scripts/build_demo_data.py
Reads  data/history/ (committed) + the latest ATT&CK release (downloaded if missing)
Writes data/processed/ (passages, vectors, warehouse.duckdb), dbt/target/run_results.json, data/processed/build_stamp.txt

data/processed/ and dbt/target/ aren't committed, so the hosted app builds them on first start. Unlike
run_pipeline.py there is no KEV fetch, changelog entry or eval: it only rebuilds from what is committed. Each step
is its own process, so peak memory is one step's (680 MB measured for embedding), not the sum.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script dir from the path
from run_pipeline import DBT_RESULTS_PATH, PY, ROOT, WAREHOUSE_PATH, latest_release_file

# --- CONFIG ---
PROCESSED_DIR = ROOT / "data/processed"
STAMP_PATH = PROCESSED_DIR / "build_stamp.txt"
OUTPUTS = [PROCESSED_DIR / "index.json", PROCESSED_DIR / "vectors.npy", PROCESSED_DIR / "marker_vectors.npy",
           WAREHOUSE_PATH, DBT_RESULTS_PATH]
INPUT_GLOBS = ["data/history/*", "dbt/dbt_project.yml", "dbt/models/**/*", "scripts/parse_stix.py",
               "scripts/build_passages.py", "scripts/embed_passages.py"]


def inputs_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(f for g in INPUT_GLOBS for f in ROOT.glob(g) if f.is_file()):
        h.update(str(p.relative_to(ROOT)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def needs_build() -> bool:
    """Build if an output is missing, or if this script built them from inputs that have since changed.

    No stamp means a local run_pipeline.py build, which is trusted as is.
    """
    if not all(p.exists() for p in OUTPUTS):
        return True
    return STAMP_PATH.exists() and STAMP_PATH.read_text().strip() != inputs_hash()


def main() -> None:
    steps = [
        [PY, "-I", "scripts/parse_stix.py", str(latest_release_file(offline=False))],
        [PY, "-I", "scripts/build_passages.py"],
        [str(Path(PY).with_name("dbt")), "build", "--project-dir", "dbt", "--profiles-dir", "dbt", "--quiet"],
        [PY, "-I", "scripts/embed_passages.py"],
    ]
    for args in steps:
        print(f"$ {Path(args[0]).name} {' '.join(args[1:])}", flush=True)
        subprocess.run(args, cwd=ROOT, check=True)
    STAMP_PATH.write_text(inputs_hash())
    print("Demo data built.")


if __name__ == "__main__":
    main()
