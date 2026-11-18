-- One row per pipeline run that fetched KEV: what changed in that run.
select
    run_at,
    any_value(catalog_version) as catalog_version,
    count(*) filter (where change = 'added') as added,
    count(*) filter (where change = 'changed') as changed,
    count(*) filter (where change = 'removed') as removed,
    max(baseline_count) as baseline_count
from {{ ref('stg_kev_history') }}
group by run_at
order by run_at
