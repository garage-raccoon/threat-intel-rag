"""Data pipeline page: how the knowledge base keeps itself current.

Reads the dbt marts in data/processed/warehouse.duckdb, dbt's run_results.json, and the committed history files.
"""
import json
import re
from pathlib import Path

import altair as alt
import duckdb
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
WAREHOUSE_PATH = ROOT / "data/processed/warehouse.duckdb"
DBT_RESULTS_PATH = ROOT / "dbt/target/run_results.json"
KEV_META_PATH = ROOT / "data/history/kev_meta.json"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
CHANGELOG_ENTRIES_SHOWN = 5
RECENT_KEV_SHOWN = 8
KEV_MONTHS_SHOWN = 24
# Categorical slots 1-3, validated with the dataviz palette checker in both modes (adjacent CVD ΔE >= 9.2).
SERIES = {"light": ["#2a78d6", "#eb6834", "#1baf7a"], "dark": ["#3987e5", "#d95926", "#199e70"]}
SURFACE = {"light": "#fcfcfb", "dark": "#1a1a19"}


@st.cache_data
def query(sql: str):
    with duckdb.connect(str(WAREHOUSE_PATH), read_only=True) as con:
        return con.sql(sql).df()


def dbt_tests() -> list[tuple[str, str]]:
    results = json.loads(DBT_RESULTS_PATH.read_text())["results"]
    # unique_id looks like test.<project>.<test_name>[.<hash>]; drop the hash dbt appends to generic tests
    return [(re.sub(r"\.[0-9a-f]{10}$", "", r["unique_id"].split(".", 2)[2]), r["status"])
            for r in results if r["unique_id"].startswith("test.")]


def changelog_entries(n: int) -> list[str]:
    text = CHANGELOG_PATH.read_text(encoding="utf-8")
    return ["## " + e.strip() for e in text.split("\n## ")[1:n + 1]]


mode = "dark" if st.context.theme.type == "dark" else "light"
colors, surface = SERIES[mode], SURFACE[mode]

st.title("Data pipeline")
st.markdown("The knowledge base updates itself. A scheduled GitHub Actions job runs on the **1st and 15th of each "
            "month**: it checks CISA's KEV feed (downloading only if it changed), checks for a new ATT&CK release, "
            "rebuilds the search passages, runs **dbt** models and data tests in **DuckDB**, re-embeds only the "
            "passages that changed, reruns the free search evaluation, and writes a changelog entry.")

if not WAREHOUSE_PATH.exists() or not DBT_RESULTS_PATH.exists():
    st.error("The warehouse hasn't been built yet. Run `.venv/bin/python -I scripts/run_pipeline.py --offline`.")
    st.stop()

releases = query("SELECT * FROM attack_release_summary ORDER BY version_order")
kev_meta = json.loads(KEV_META_PATH.read_text())
tests = dbt_tests()
passed = sum(status == "pass" for _, status in tests)
latest = releases.iloc[-1]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Last pipeline run", kev_meta["last_checked"][:10])
c2.metric("ATT&CK release", str(latest["version"]), help=f"{len(releases)} releases tracked since 2018")
c3.metric("KEV entries", f"{kev_meta['count']:,}", help=f"CISA catalog version {kev_meta['catalog_version']}")
c4.metric("dbt data tests", f"{passed}/{len(tests)} passed")

st.subheader("ATT&CK has changed in every major release")
st.caption("Active Enterprise ATT&CK techniques per release, rebuilt from all 43 published releases "
           "(`attack_release_summary` dbt model). This project answers from two tactics; the history covers all.")
base = alt.Chart(releases).encode(x=alt.X("approx_release_date:T", title=None))
tooltip = [alt.Tooltip("version:N", title="Release"), alt.Tooltip("approx_release_date:T", title="Released"),
           alt.Tooltip("techniques_active:Q", title="Active techniques"), alt.Tooltip("added:Q", title="Added"),
           alt.Tooltip("revoked:Q", title="Revoked")]
line = base.mark_line(color=colors[0], strokeWidth=2, interpolate="step-after").encode(
    y=alt.Y("techniques_active:Q", title="Active techniques"))
points = base.mark_point(color=colors[0], filled=True, size=64, opacity=0, stroke=surface, strokeWidth=2).encode(
    y="techniques_active:Q", tooltip=tooltip)
hover = alt.selection_point(on="pointerover", nearest=True, fields=["approx_release_date"], empty=False)
points = points.add_params(hover).encode(opacity=alt.condition(hover, alt.value(1), alt.value(0)))
notes = releases[releases["version"].isin(["7.0", "19.0"])].assign(
    note=lambda d: d["version"].map({"7.0": "v7.0: sub-techniques introduced (+302, 129 revoked)",
                                     "19.0": "v19.0: 198 techniques moved tactic"}))
labels = alt.Chart(notes).mark_text(align="right", dx=-8, dy=-10, fontSize=12).encode(
    x="approx_release_date:T", y="techniques_active:Q", text="note:N")
st.altair_chart((line + points + labels).properties(height=320), width="stretch")

st.subheader("What changed in each release")
changes = releases.assign(retired=releases["revoked"] + releases["deprecated"])
long = changes.melt(id_vars=["version", "version_order"], value_vars=["added", "changed", "retired"],
                    var_name="change", value_name="techniques")
long["change"] = long["change"].map({"added": "Added", "changed": "Changed", "retired": "Revoked or deprecated"})
order = ["Added", "Changed", "Revoked or deprecated"]
bars = alt.Chart(long[long["techniques"] > 0]).mark_bar(stroke=surface, strokeWidth=2).encode(
    x=alt.X("version:N", sort=alt.SortField("version_order"), title="ATT&CK release", axis=alt.Axis(labelAngle=-90)),
    y=alt.Y("sum(techniques):Q", title="Techniques"),
    color=alt.Color("change:N", scale=alt.Scale(domain=order, range=colors), sort=order,
                    legend=alt.Legend(title=None, orient="top")),
    order=alt.Order("change_order:Q"),
    tooltip=[alt.Tooltip("version:N", title="Release"), alt.Tooltip("change:N", title="Change"),
             alt.Tooltip("techniques:Q", title="Techniques")],
).transform_calculate(change_order=f"indexof({order}, datum.change)")
st.altair_chart(bars.properties(height=300), width="stretch")
st.caption("\"Changed\" = the technique's name, tactics, platforms or description differs from the previous release. "
           "Releases with no changes have no bar.")
with st.expander("Table view: every release"):
    st.dataframe(releases.drop(columns=["version_order"]), hide_index=True, width="stretch")

st.subheader("CISA Known Exploited Vulnerabilities")
st.caption(f"Each run sends the feed's last ETag; CISA answers *not modified* unless the catalog changed. "
           f"Last result: **{kev_meta['last_result'].replace('_', ' ')}** (catalog {kev_meta['catalog_version']}).")
monthly = query(f"""
    SELECT DATE_TRUNC('month', date_added) AS month, COUNT(*) AS added
    FROM stg_kev
    WHERE date_added >= DATE_TRUNC('month', CURRENT_DATE) - INTERVAL {KEV_MONTHS_SHOWN - 1} MONTH
    GROUP BY 1 ORDER BY 1""")
kev_bars = alt.Chart(monthly).mark_bar(color=colors[0], cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
    x=alt.X("month:T", title=None, timeUnit="yearmonth"),
    y=alt.Y("added:Q", title="Entries added"),
    tooltip=[alt.Tooltip("month:T", title="Month", format="%b %Y"), alt.Tooltip("added:Q", title="Added to KEV")])
left, right = st.columns([3, 2])
with left:
    st.markdown(f"**Entries added to the catalog per month** (last {KEV_MONTHS_SHOWN} months)")
    st.altair_chart(kev_bars.properties(height=260), width="stretch")
with right:
    st.markdown("**Most recently added**")
    recent = query(f"""SELECT cve_id AS "CVE", vulnerability_name AS "Vulnerability", date_added AS "Added"
                       FROM stg_kev ORDER BY date_added DESC, cve_id LIMIT {RECENT_KEV_SHOWN}""")
    st.dataframe(recent, hide_index=True, width="stretch")
st.markdown("**Pipeline runs that changed KEV** (`kev_runs` dbt model)")
st.dataframe(query("SELECT * FROM kev_runs ORDER BY run_at DESC"), hide_index=True, width="stretch")

st.subheader("Data tests")
st.caption("dbt tests run on every pipeline run. Tests guarding the search passages stop the run if they fail; "
           "the rest warn, and the warning is listed in the changelog.")
STATUS_LABELS = {"pass": "✓ pass", "warn": "⚠ warning"}
with st.expander(f"{passed}/{len(tests)} dbt tests passed on the last run"):
    st.dataframe([{"Test": name, "Status": STATUS_LABELS.get(status, f"✗ {status}")} for name, status in tests],
                 hide_index=True, width="stretch")

st.subheader("Changelog")
st.caption("Written by `scripts/run_pipeline.py` after every run and committed with the data, so history stays in git.")
for entry in changelog_entries(CHANGELOG_ENTRIES_SHOWN):
    with st.container(border=True):
        st.markdown(entry.replace("## ", "#### ", 1))
