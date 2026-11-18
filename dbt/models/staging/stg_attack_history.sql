-- One row per technique per ATT&CK release (backfilled from all releases: scripts/backfill_attack_history.py).
select
    h.version,
    v.version_order,
    h.attack_id,
    h.name,
    h.is_subtechnique = 'true' as is_subtechnique,
    h.tactics,
    h.platforms,
    h.status,
    h.content_hash,
    h.stix_modified
from read_csv('data/history/attack_history.csv', header = true, all_varchar = true) as h
join {{ ref('stg_attack_versions') }} as v using (version)
