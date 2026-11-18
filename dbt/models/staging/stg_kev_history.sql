-- Append-only log of KEV changes, one line per added / changed / removed CVE per run (plus one baseline line).
-- Columns are declared explicitly: until a run records a change, the log holds only the baseline line, which has
-- no cveID, and schema auto-detection would fail on it.
select
    cast(run_at as timestamp) as run_at,
    catalog_version,
    change,
    cveID as cve_id,
    count as baseline_count
from read_json(
    'data/history/kev_history.jsonl',
    format = 'newline_delimited',
    columns = {run_at: 'VARCHAR', catalog_version: 'VARCHAR', change: 'VARCHAR', cveID: 'VARCHAR', count: 'BIGINT'}
)
