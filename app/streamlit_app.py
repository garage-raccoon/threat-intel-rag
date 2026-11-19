"""Threat Intel RAG demo: entry point and page navigation.

Run locally:  .venv/bin/streamlit run app/streamlit_app.py   (http://localhost:8501)
Hosted on Streamlit Community Cloud: the first start on a server builds the generated data, which isn't committed.
"""
import os
import subprocess
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)  # dbt's staging views read data/history/ by relative path
sys.path.insert(0, str(ROOT / "scripts"))
from build_demo_data import needs_build  # noqa: E402

st.set_page_config(page_title="Threat Intel RAG", page_icon="🛡️", layout="wide")


@st.cache_resource(show_spinner="First start on this server: building the search index and data warehouse "
                                "(about a minute)…")
def build_data() -> None:
    # A separate process, so the build's memory is freed before the search model loads.
    if needs_build():
        proc = subprocess.run([sys.executable, "-I", "scripts/build_demo_data.py"], cwd=ROOT,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout).strip()[-2000:])


try:
    build_data()
except RuntimeError as e:
    st.error("Building the demo data failed. Details:")
    st.code(str(e))
    st.stop()

st.navigation([
    st.Page("search.py", title="Search", icon=":material/search:", default=True),
    st.Page("pipeline.py", title="Data pipeline", icon=":material/sync:"),
    st.Page("evaluation.py", title="Evaluation", icon=":material/fact_check:"),
]).run()
