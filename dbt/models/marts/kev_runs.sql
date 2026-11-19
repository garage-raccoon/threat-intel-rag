-- One row per pipeline run that fetched KEV: what changed in that run.
SELECT
    run_at,
    ANY_VALUE(catalog_version) AS catalog_version,
    COUNT(*) FILTER (WHERE change = 'added') AS added,
    COUNT(*) FILTER (WHERE change = 'changed') AS changed,
    COUNT(*) FILTER (WHERE change = 'removed') AS removed,
    MAX(baseline_count) AS baseline_count
FROM {{ ref('stg_kev_history') }}
GROUP BY run_at
ORDER BY run_at
