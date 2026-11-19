"""Threat Intel RAG demo: entry point and page navigation (Stage 3).

Run locally:  .venv/bin/streamlit run app/streamlit_app.py   (http://localhost:8501)
"""
import streamlit as st

st.set_page_config(page_title="Threat Intel RAG", page_icon="🛡️", layout="wide")
st.navigation([
    st.Page("search.py", title="Search", icon=":material/search:", default=True),
    st.Page("pipeline.py", title="Data pipeline", icon=":material/sync:"),
    st.Page("evaluation.py", title="Evaluation", icon=":material/fact_check:"),
]).run()
