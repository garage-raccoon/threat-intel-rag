-- One row per ATT&CK release: how many techniques were added, changed, revoked, deprecated, ...
select
    v.version,
    v.version_order,
    v.approx_release_date,
    v.techniques_active,
    count(*) filter (where c.change_type = 'added') as added,
    count(*) filter (where c.change_type = 'changed') as changed,
    count(*) filter (where c.change_type = 'changed' and c.tactics_changed) as tactics_changed,
    count(*) filter (where c.change_type = 'revoked') as revoked,
    count(*) filter (where c.change_type = 'deprecated') as deprecated,
    count(*) filter (where c.change_type = 'reactivated') as reactivated,
    count(*) filter (where c.change_type = 'dropped') as dropped
from {{ ref('stg_attack_versions') }} as v
left join {{ ref('attack_technique_changes') }} as c using (version)
group by all
order by v.version_order
