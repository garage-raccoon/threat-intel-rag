-- Append-only log of KEV changes, one line per added / changed / removed CVE per run (plus one baseline line).
SELECT
    CAST(run_at AS TIMESTAMP) AS run_at,
    catalog_version,
    change,
    cveID AS cve_id,
    count AS baseline_count
FROM {{ source('history', 'kev_history') }}
